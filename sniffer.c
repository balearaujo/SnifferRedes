#define HAVE_REMOTE
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <pcap.h> 
#include "headers.h"
extern pcap_t* MostrarSelectorInterfaces(HINSTANCE hInstance, int *out_link_length); //nnvea funcion para seleccion

// Identificadores de las áreas de la interfaz
#define ID_LISTVIEW_TRAFICO 101
#define ID_TEXT_ESTRUCTURA  102
#define ID_TEXT_RAW         103
#define WM_NUEVO_PAQUETE (WM_USER + 1)

// Variables globales para los componentes visuales
HWND hwndLista, hwndEstructura, hwndRaw;
pcap_t *capdev = NULL;
int link_hdr_length = 0;

// Estructura interna para almacenar temporalmente los paquetes capturados
typedef struct {
    int id;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int protocol;
    int length;
    char detalle[1024];
    char raw_hex[2048];
} PacketMemory;

PacketMemory historial_paquetes[1000]; // Buffer para los últimos 1000 paquetes
int total_paquetes = 0;

// --- FUNCIÓN DE CAPTURA CORREGIDA ---
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    
    // Verificación dinámica según el tipo de cabecera de red activa
    if (link_hdr_length == 14) {
        // Si es Ethernet clásico, el protocolo IPv4 (0x0800) está en los bytes 12 y 13
        if (packet[12] != 0x08 || packet[13] != 0x00) return; 
    } 
    else if (link_hdr_length == 4) {
        // Si es Loopback / DLT_NULL (127.0.0.1)
        if (packet[0] != 2 && packet[0] != 24 && packet[2] != 0x08) {
            // Dejamos pasar para asegurar la captura en adaptadores virtuales de Windows
        }
    }

    // 2. Calcular posición de la cabecera IP dinámicamente
    const u_char *ip_ptr = packet + link_hdr_length;
    
    // Validación de seguridad elemental
    if (pkthdr->caplen < (bpf_u_int32)(link_hdr_length + sizeof(struct ip_header))) return;

    struct ip_header *ip_hdr = (struct ip_header *)ip_ptr;
    
    // Filtrar: Solo TCP (6) o UDP (17)
    if (ip_hdr->ip_p != 6 && ip_hdr->ip_p != 17) return;

    // Evitar desbordamiento de memoria del buffer (máximo 1000 paquetes)
    if (total_paquetes >= 1000) return; 

    int indice = total_paquetes;
    historial_paquetes[indice].id = indice + 1;
    historial_paquetes[indice].length = pkthdr->len;
    historial_paquetes[indice].protocol = ip_hdr->ip_p;

    // Extraer IPs binarias a formato de texto legible
    inet_ntop(AF_INET, &(ip_hdr->ip_src), historial_paquetes[indice].src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), historial_paquetes[indice].dst_ip, INET_ADDRSTRLEN);

    int ip_hdr_len = (ip_hdr->ip_v_hl & 0x0F) * 4;
    char buffer_estructura[1024] = {0};
    char buffer_hex[2048] = {0};

    // Armar la información estructurada básica (Capa de Red - Área 2)
    sprintf(buffer_estructura, 
            "=== CAPA DE RED (IPv4) ===\r\n"
            "|- Versi\xF3n: %d\r\n"
           "|- Tama\xF1o de Cabecera: %d bytes\r\n"
            "|- TTL (Time to Live): %d\r\n"
            "|- Protocolo: %d (TCP=6, UDP=17)\r\n", 
            (ip_hdr->ip_v_hl >> 4), ip_hdr_len, ip_hdr->ip_ttl, ip_hdr->ip_p);

    // Análisis detallado si el protocolo es TCP
    if (ip_hdr->ip_p == 6) {
        const u_char *tcp_packet_ptr = ip_ptr + ip_hdr_len;
        struct tcp_header *tcp_hdr = (struct tcp_header *)tcp_packet_ptr;
        int tcp_hdr_len = (tcp_hdr->th_off_x2 >> 4) * 4;

        char sub_tcp[512];
        sprintf(sub_tcp, 
                "\r\n=== CAPA DE TRANSPORTE (TCP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n", 
                ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
        strcat(buffer_estructura, sub_tcp);

        // Cálculo exacto del segmento de datos (Payload)
        const u_char *payload_ptr = tcp_packet_ptr + tcp_hdr_len;
        int total_ip_len = ntohs(ip_hdr->ip_len);
        int payload_len = total_ip_len - (ip_hdr_len + tcp_hdr_len);
        int limite_bytes = (payload_len > 32) ? 32 : payload_len;

        if (payload_len > 0) {
            char temp_hex[32];
            strcat(buffer_hex, "HEXDUMP (Primeros 32 bytes):\r\n");
            for (int i = 0; i < limite_bytes; i++) {
                sprintf(temp_hex, "%02X ", payload_ptr[i]);
                strcat(buffer_hex, temp_hex);
            }
            strcat(buffer_hex, "\r\n\r\nTEXTO:\r\n");
            for (int i = 0; i < limite_bytes; i++) {
                if (payload_ptr[i] >= 32 && payload_ptr[i] <= 126) {
                    char c = (char)payload_ptr[i];
                    strncat(buffer_hex, &c, 1);
                } else {
                    strcat(buffer_hex, ".");
                }
            }
        } else {
            strcpy(buffer_hex, "[Paquete de control TCP vacio o sin datos de aplicacion]");
        }
    }
    // Análisis detallado si el protocolo es UDP
    else if (ip_hdr->ip_p == 17) {
        const u_char *udp_packet_ptr = ip_ptr + ip_hdr_len;
        uint16_t sport = ntohs(*(uint16_t *)(udp_packet_ptr));
        uint16_t dport = ntohs(*(uint16_t *)(udp_packet_ptr + 2));
        
        char sub_udp[512];
        sprintf(sub_udp, 
                "\r\n=== CAPA DE TRANSPORTE (UDP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n", sport, dport);
        strcat(buffer_estructura, sub_udp);
        strcpy(buffer_hex, "[Datos de datagrama UDP cifrados o binarios]");
    }

    // Guardar buffers en la memoria de la aplicación de forma limpia
    strcpy(historial_paquetes[indice].detalle, buffer_estructura);
    strcpy(historial_paquetes[indice].raw_hex, buffer_hex);

    total_paquetes++;

    // Despachamos el aviso de forma segura al hilo principal pasando el índice
    PostMessage(GetParent(hwndLista), WM_NUEVO_PAQUETE, (WPARAM)indice, 0);
}

// Hilo secundario para que pcap_loop no bloquee la interfaz gráfica
DWORD WINAPI HiloCaptura(LPVOID lpParam) {
    pcap_loop(capdev, 0, call_me, NULL);
    return 0;
}

// Manejador de eventos de la ventana
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            // Área 1: Lista de Tráfico
            hwndLista = CreateWindowEx(0, WC_LISTVIEW, "", 
                WS_VISIBLE | WS_CHILD | LVS_REPORT | WS_BORDER, 
                10, 10, 760, 200, hwnd, (HMENU)ID_LISTVIEW_TRAFICO, NULL, NULL);
            
            ListView_SetExtendedListViewStyle(hwndLista, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMN lvc;
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.cx = 50;  lvc.pszText = "No.";       ListView_InsertColumn(hwndLista, 0, &lvc);
            lvc.cx = 160; lvc.pszText = "IP Origen";  ListView_InsertColumn(hwndLista, 1, &lvc);
            lvc.cx = 160; lvc.pszText = "IP Destino"; ListView_InsertColumn(hwndLista, 2, &lvc);
            lvc.cx = 80;  lvc.pszText = "Protocolo"; ListView_InsertColumn(hwndLista, 3, &lvc);
            lvc.cx = 90;  lvc.pszText = "Longitud";  ListView_InsertColumn(hwndLista, 4, &lvc);

            // Área 2: Detalle Estructurado
            hwndEstructura = CreateWindowEx(0, "EDIT", "Selecciona un paquete en la lista de arriba...", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 
                10, 220, 760, 160, hwnd, (HMENU)ID_TEXT_ESTRUCTURA, NULL, NULL);

            // Área 3: Contenido RAW Hexdump
            hwndRaw = CreateWindowEx(0, "EDIT", "Volcado Hexadecimal...", 
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 
                10, 395, 760, 150, hwnd, (HMENU)ID_TEXT_RAW, NULL, NULL);
            
            HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, 
                                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, 
                                    FIXED_PITCH | FF_MODERN, "Courier New");
            SendMessage(hwndRaw, WM_SETFONT, (WPARAM)hFont, TRUE);
            break;
        }
        case WM_NOTIFY: {
            LPNMHDR nmhdr = (LPNMHDR)lParam;
            if (nmhdr->idFrom == ID_LISTVIEW_TRAFICO && nmhdr->code == NM_CLICK) {
                int itemIndex = ListView_GetNextItem(hwndLista, -1, LVNI_SELECTED);
                if (itemIndex != -1 && itemIndex < total_paquetes) {
                    SetWindowText(hwndEstructura, historial_paquetes[itemIndex].detalle);
                    SetWindowText(hwndRaw, historial_paquetes[itemIndex].raw_hex);
                }
            }
            break;
        }
        // CASO INTER-HILO CORRECTO: Dibuja las filas de forma síncrona y segura
        case WM_NUEVO_PAQUETE: {
            int indice = (int)wParam;
            if (indice >= 1000) break;

            LVITEM lvi = {0};
            lvi.mask = LVIF_TEXT;
            lvi.iItem = indice;
            
            char s_id[16], s_prot[16], s_len[16];
            sprintf(s_id, "%d", historial_paquetes[indice].id);
            sprintf(s_prot, "%d", historial_paquetes[indice].protocol);
            sprintf(s_len, "%d", historial_paquetes[indice].length);

            lvi.iSubItem = 0; 
            lvi.pszText = s_id; 
            ListView_InsertItem(hwndLista, &lvi);
            
            ListView_SetItemText(hwndLista, indice, 1, historial_paquetes[indice].src_ip);
            ListView_SetItemText(hwndLista, indice, 2, historial_paquetes[indice].dst_ip);
            ListView_SetItemText(hwndLista, indice, 3, s_prot);
            ListView_SetItemText(hwndLista, indice, 4, s_len);
            
            UpdateWindow(hwndLista);
            break;
        }
        case WM_DESTROY:
            if(capdev) pcap_breakloop(capdev);
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Llamamos al archivo nuevo para que haga la magia
    capdev=MostrarSelectorInterfaces(hInstance, &link_hdr_length);
    
    if (capdev==NULL){
        return 0; //si falla la funcion
    }

    //elimine esta seccion para poder elegir entre los device y salta directo
    
    WNDCLASSEX wincl = {0};
    wincl.hInstance = hInstance;
    wincl.lpszClassName = "SnifferGUI";
    wincl.lpfnWndProc = WindowProcedure;
    wincl.cbSize = sizeof(WNDCLASSEX);
    wincl.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wincl.hCursor = LoadCursor(NULL, IDC_ARROW);
    wincl.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

    if (!RegisterClassEx(&wincl)) return 0;

    HWND hwnd = CreateWindowEx(0, "SnifferGUI", "Packet Sniffer Oficial - Equipos de Redes", 
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE | WS_CLIPCHILDREN, 
        CW_USEDEFAULT, CW_USEDEFAULT, 795, 600, HWND_DESKTOP, NULL, hInstance, NULL);

    CreateThread(NULL, 0, HiloCaptura, NULL, 0, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}