#include <pcap.h>
#include <windows.h>
#include <stdio.h>
#include <commctrl.h>


// Estructura para empaquetar los resultados de la selección
typedef struct{
    pcap_t *capdev; //puntero al dispositivo
    int link_length; //tam de cabecera
} seleccion;

// Prototipo de la función que llamará tu WinMain principal
pcap_t* MostrarSelectorInterfaces(HINSTANCE hInstance, int *out_link_length);


#define LISTA 201
#define ID_BOTON_ACEPTAR    202

// Aqui guarda nuestra seleccion
static seleccion resultado={NULL, 0};

// Manejador de eventos exclusivo del Selector
LRESULT CALLBACK DialogoInterfacesProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static pcap_if_t *alldevs=NULL; //todas las tarjetas de red enlazadas
    static HWND hwndLista; //de los gráficos 

    switch (message) {
        case WM_CREATE: { //si la ventana se esta creando
            char error_buffer[PCAP_ERRBUF_SIZE]; //oara fallos
            
            CreateWindowExA(0, "STATIC", "Selecciona la interfaz de red para capturar:", 
                        WS_VISIBLE | WS_CHILD, 15, 15, 350, 20, hwnd, NULL, NULL, NULL);

            hwndLista = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "", 
                                    WS_VISIBLE | WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_BORDER, 
                                    15, 35, 450, 180, hwnd, (HMENU)LISTA, NULL, NULL);

            CreateWindowExA(0, "BUTTON", "Aceptar", //boton de acentar 
                        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 
                        325, 225, 140, 32, hwnd, (HMENU)ID_BOTON_ACEPTAR, NULL, NULL);

            if (pcap_findalldevs(&alldevs, error_buffer)==-1){ //busqueda de las interfaces
                MessageBoxA(hwnd, "Error al buscar interfaces de red", "Error", MB_ICONERROR);
                DestroyWindow(hwnd);
                return 0;
            }

            int index=0;
            for (pcap_if_t *d=alldevs; d != NULL; d = d->next) {
                char texto[512];
                if (d->description) {
                    sprintf(texto, "%s", d->description); //muestra la descricion de cada tarjeta
                } else {
                    sprintf(texto, "%s (Sin descripcion)", d->name); //sino tiene pues su niombre
                }
                
                SendMessageA(hwndLista, LB_ADDSTRING, 0, (LPARAM)texto); //agrega el texyo al combo
                SendMessageA(hwndLista, LB_SETITEMDATA, index, (LPARAM)d);
                index++; //incrementa contador
            }

            if (index==0){ //si nunca avanzó mostrar que no habian interfaces disponibles
                MessageBoxA(hwnd, "No se encontraron interfaces disponibles", "Error", MB_ICONWARNING);
                pcap_freealldevs(alldevs);
                DestroyWindow(hwnd);
            } else {
                SendMessageA(hwndLista, LB_SETCURSEL, 0, 0);
            }
            break;
        }
        case WM_COMMAND: { //interaccion del usuario
            // Doble clic rápido en un elemento de la lista también inicia la captura (Igual que Wireshark)
            if (LOWORD(wParam) == LISTA && HIWORD(wParam) == LBN_DBLCLK) {
                SendMessageA(hwnd, WM_COMMAND, MAKEWPARAM(ID_BOTON_ACEPTAR, 0), 0);
            }

            if (LOWORD(wParam) == ID_BOTON_ACEPTAR) {
                int sel=SendMessageA(hwndLista, LB_GETCURSEL, 0, 0); // LB_GETCURSEL es para ListBox
                if (sel != LB_ERR) {
                    pcap_if_t *d = (pcap_if_t*)SendMessageA(hwndLista, LB_GETITEMDATA, sel, 0);
                    char error_buffer[PCAP_ERRBUF_SIZE];
                    
                    resultado.capdev=pcap_open_live(d->name, 65536, 1, 1000, error_buffer);  //guarfar resultado
                    
                    if (resultado.capdev == NULL) {
                        MessageBoxA(hwnd, "No se pudo abrir la interfaz", "Error", MB_ICONERROR); 
                    } else { //dependiendo de la interfaz el tamaño (14 bytes de ethernet o 4 de loopback)
                        int link_hdr_type = pcap_datalink(resultado.capdev); //identidica que tipo de enlace es
                        if (link_hdr_type == DLT_EN10MB) resultado.link_length = 14;
                        else if (link_hdr_type == DLT_NULL) resultado.link_length = 4;
                        else resultado.link_length = 0;

                        pcap_freealldevs(alldevs);
                        alldevs = NULL;
                        PostQuitMessage(1); 
                    }
                }
            }
            break;
        }
        case WM_CLOSE:
            if (alldevs) pcap_freealldevs(alldevs);
            PostQuitMessage(0); 
            break;
        default:
            return DefWindowProcA(hwnd, message, wParam, lParam);
    }
    return 0;
}

pcap_t* MostrarSelectorInterfaces(HINSTANCE hInstance, int *out_link_length) {
    WNDCLASSEXA diagcl = {0};
    diagcl.hInstance = hInstance;
    diagcl.lpszClassName = "SelectorInterfaces";
    diagcl.lpfnWndProc = DialogoInterfacesProc;
    diagcl.cbSize = sizeof(WNDCLASSEXA);
    diagcl.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    diagcl.hCursor = LoadCursor(NULL, IDC_ARROW);
    diagcl.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassExA(&diagcl);

    HWND hwndDiag = CreateWindowExA(WS_EX_DLGMODALFRAME, "SelectorInterfaces", "Interfaces Disponibles - Npcap", 
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 
        CW_USEDEFAULT, CW_USEDEFAULT, 495, 310, NULL, NULL, hInstance, NULL);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    *out_link_length = resultado.link_length;
    return resultado.capdev; 
}