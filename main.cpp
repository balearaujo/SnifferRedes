#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <pcap.h>
#include "headers.h"
#include <math.h>

#ifndef PI
#define PI 3.14159265358979323846
#endif

// Variables DirectX
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext*   g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*  g_pSwapChain = nullptr;
static UINT  g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Estado de la aplicacion
enum AppState { STATE_SELECT_INTERFACE, STATE_DASHBOARD };
AppState currentState = STATE_SELECT_INTERFACE; //empieza la aplicacióin en el estado de seleccionar interfaz

pcap_if_t *alldevs = nullptr; //Interfaces detectadas por ncap
char errbuf[PCAP_ERRBUF_SIZE]; //buffer para almacenar errores

// Variables de UIDE LAS VENTANAS/PANELES
bool show_pie_chart = true;
bool show_io_graph = true;
bool show_vulnerable_tab = true;

namespace ImGui {
    double g_CaptureElapsedTime = 0; //tiempo transcurrido
}

float io_graph_history[120] = {0}; //historial del ancho de banda
double last_io_time = 0;
unsigned long long last_total_bytes = 0;
ImFont* monospace_font = nullptr;
int selected_packet_index = -1; //indice del paquete seleccionado
char filter_ip_src[64] = "";
char filter_ip_dst[64] = "";
char filter_port_src[16] = "";
char filter_port_dst[16] = "";
int filter_proto_index = 0; //indice para seleccionar los filtros de protocolo
const char* proto_options[] = { "Todos", "TCP", "UDP", "ICMP", "ARP", "IPv6", "HTTP", "TLSv1.3", "DNS", "SSDP", "DHCP" }; //opciones desplegables de ptoyocolo

//variables de capture.cpp
extern volatile bool capture_running;
extern std::chrono::steady_clock::time_point capture_start_time;

void render_hex_view(const std::string& hex_str) {
    ImGui::TextUnformatted(hex_str.c_str());
}

void DrawPieChart(ImDrawList* draw_list, ImVec2 center, float radius, float start_angle, float end_angle, ImU32 color) { //como se dibuja la grafica de pastel 
    if (end_angle - start_angle <= 0.0f) return;
    draw_list->PathLineTo(center); 
    draw_list->PathArcTo(center, radius, start_angle, end_angle, 32); //angulo
    draw_list->PathFillConvex(color); //color que llena
}

void RenderPieChartPanel() { 
    std::lock_guard<std::mutex> lock(historial_mutex);
    if (global_stats.total == 0) {
        ImGui::Text("Esperando trafico...");
        return; 
    }
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float radius = 80.0f;
    ImVec2 center = ImVec2(p.x + radius + 20, p.y + radius + 20);
    
    float current_angle = 0.0f;
    float total = (float)global_stats.total;

    struct PieData { float count; ImU32 color; const char* name; };
    PieData data[] = {
        { (float)global_stats.tcp, IM_COL32(255, 50, 50, 255), "TCP" },
        { (float)global_stats.udp, IM_COL32(50, 150, 255, 255), "UDP" },
        { (float)global_stats.icmp, IM_COL32(50, 255, 50, 255), "ICMP" },
        { (float)global_stats.arp, IM_COL32(255, 255, 50, 255), "ARP" },
        { (float)global_stats.other, IM_COL32(180, 180, 180, 255), "Otros" }
    };

    for (int i = 0; i < 5; i++) {
        if (data[i].count > 0) {
            float sweep = (data[i].count / total) * 2.0f * PI;
            DrawPieChart(draw_list, center, radius, current_angle, current_angle + sweep, data[i].color);
            current_angle += sweep;
        }
    }
    
    ImGui::Dummy(ImVec2(radius * 2 + 40, radius * 2 + 40));
    
    for (int i = 0; i < 5; i++) {
        ImGui::PushStyleColor(ImGuiCol_Text, data[i].color);
        ImGui::Text("%s: %.0f", data[i].name, data[i].count);
        ImGui::PopStyleColor();
    }
}

// Comparador Case-Insensitive para los filtros de la UI
bool contains_icase(const std::string& str, const std::string& substr) {
    auto it = std::search(
        str.begin(), str.end(),
        substr.begin(), substr.end(),
        [](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); }
    );
    return (it != str.end());
}

int main(int, char**) {
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui Example", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Sniffer - Captura de paquetes", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    
    // Cargar fuente TTF si existe (mejorando 200% el estilo pixelado)
    ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\segoeui.ttf", 18.0f);
    if (!font) {
        io.Fonts->AddFontDefault();
    }
    
    // Load Monospace Font for Hexdump and Detalle
    monospace_font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\consola.ttf", 16.0f);
    if (!monospace_font) monospace_font = io.Fonts->AddFontDefault();

    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        alldevs = nullptr;
    }

    //aplicacion loop
    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        //si el usuario renderizo las ventanas 
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        //comenzar con un nuevo frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0)); //ventana completa
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Main", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);

        if (currentState == STATE_SELECT_INTERFACE) { //selecciona la interfaz
            ImGui::Text("Selecciona la interfaz de red para capturar:");
            ImGui::Separator();
            if (!alldevs) {
                ImGui::TextColored(ImVec4(1, 0, 0, 1), "Error al buscar interfaces de red."); //validacion de encontrar las interfaces
            } else {
                if (ImGui::BeginListBox("##interfaces", ImVec2(-FLT_MIN, -FLT_MIN))) {
                    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
                        char label[512];
                        sprintf(label, "%s", d->description ? d->description : "Interfaz Desconocida"); //mostrar descripción
                        if (ImGui::Selectable(label)) { //si el usuario selecciona
                            pcap_t *capdev = pcap_open_live(d->name, 65536, 1, 1, errbuf); //guardar el usuario
                            if (capdev) {
                                int link_hdr_type = pcap_datalink(capdev);
                                int link_len = (link_hdr_type == DLT_EN10MB) ? 14 : ((link_hdr_type == DLT_NULL) ? 4 : 0); //identifica tipo de encabezado
                                //Ethernet-> 14 bytes      //Loopback 4 bytes   
                                iniciar_captura(capdev, link_len); //iniciamos proceso
                                currentState = STATE_DASHBOARD; //cambia de pantalla de muestra del dash borard
                            }
                        }
                    }
                    ImGui::EndListBox();
                }
            }
        } else if (currentState == STATE_DASHBOARD) {
            // Toolbar
            if (ImGui::Button("Volver Atras")) {
                detener_captura(); //detiene 
                historial_paquetes.clear(); //limpiar el vector 
                global_stats = {0};
                currentState = STATE_SELECT_INTERFACE; //volver a seleccionar la interfaz
            }
            ImGui::SameLine();
            
            if (capture_running) {
                if (ImGui::Button("Pausar Captura", ImVec2(120, 0))) capture_running = false; //cambiamos el estado de la captura
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.2f, 1.0f));
                if (ImGui::Button("Reanudar Captura", ImVec2(120, 0))) capture_running = true;
                ImGui::PopStyleColor();
            }

            ImGui::SameLine();
            if (ImGui::Button("Exportar CSV")) {
                exportar_csv(); //llamar a funcion de exportar captura
            }
            ImGui::SameLine();
            if (ImGui::Button("Reiniciar Captura")) { //reimiciarcaptura
                ImGui::OpenPopup("Confirmar Reinicio");
            }
            if (ImGui::BeginPopupModal("Confirmar Reinicio", NULL, ImGuiWindowFlags_AlwaysAutoResize)) { 
                ImGui::Text("¿Estas seguro de que deseas borrar todos los paquetes?\nEsta accion no se puede deshacer.");
                ImGui::Separator();
                if (ImGui::Button("Si, Reiniciar", ImVec2(120, 0))) {
                    std::lock_guard<std::mutex> lock(historial_mutex);
                    historial_paquetes.clear();
                    global_stats = {0};
                    capture_start_time = std::chrono::steady_clock::now();
                    for(int i=0; i<120; i++) io_graph_history[i] = 0;
                    last_total_bytes = 0;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SetItemDefaultFocus();
                ImGui::SameLine();
                if (ImGui::Button("Cancelar", ImVec2(120, 0))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            ImGui::SameLine(); //menu oara seleccionar las vistas
            if (ImGui::Button("Vistas")) ImGui::OpenPopup("vistas_popup");
            if (ImGui::BeginPopup("vistas_popup")) {
                ImGui::MenuItem("Grafico Pastel", NULL, &show_pie_chart);
                ImGui::MenuItem("Grafico E/S", NULL, &show_io_graph);
                ImGui::MenuItem("Trafico Vulnerable", NULL, &show_vulnerable_tab);
                ImGui::EndPopup();
            }
            
            ImGui::SameLine();
            ImGui::Text("Filtros:");
            ImGui::SameLine();
            
            ImGui::SetNextItemWidth(120);
            ImGui::InputTextWithHint("##ip_src", "IP Origen", filter_ip_src, IM_ARRAYSIZE(filter_ip_src));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(120);
            ImGui::InputTextWithHint("##ip_dst", "IP Destino", filter_ip_dst, IM_ARRAYSIZE(filter_ip_dst));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80);
            ImGui::InputTextWithHint("##p_src", "P. Origen", filter_port_src, IM_ARRAYSIZE(filter_port_src));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80);
            ImGui::InputTextWithHint("##p_dst", "P. Destino", filter_port_dst, IM_ARRAYSIZE(filter_port_dst));
            ImGui::SameLine();
            ImGui::SetNextItemWidth(100);
            ImGui::Combo("##proto", &filter_proto_index, proto_options, IM_ARRAYSIZE(proto_options));

            ImGui::SameLine();
            ImGui::TextDisabled("(?)");
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Filtra los paquetes seleccionando IPs, Puertos o el Protocolo directamente.");
            }
            ImGui::Separator();

            // Layout
            float right_panel_width = (show_pie_chart || show_io_graph) ? 350.0f : 0.0f;
            float left_panel_width = ImGui::GetContentRegionAvail().x - right_panel_width;
            if (show_pie_chart || show_io_graph) left_panel_width -= ImGui::GetStyle().ItemSpacing.x;

            ImGui::BeginChild("LeftPanel", ImVec2(left_panel_width, 0), false);
            
            float left_panel_y = ImGui::GetContentRegionAvail().y;
            float area4_h = show_vulnerable_tab ? 180.0f : 0.0f;
            float area1_h = (left_panel_y - area4_h) * 0.5f;
            float area23_h = (left_panel_y - area4_h) * 0.5f;
            
            // Area 1: Lista (mitad superior)
            ImGui::BeginChild("Area1", ImVec2(0, area1_h), true);
            
            // Forzar texto negro y fondo blanco/gris para la tabla (para que los colores pastel se vean bien)
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 0, 0, 255));
            ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, IM_COL32(200, 200, 220, 255));
            
            if (ImGui::BeginTable("table1", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                // Header with dark text and standard background
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("No.");
                ImGui::TableSetupColumn("Tiempo");
                ImGui::TableSetupColumn("IP Origen");
                ImGui::TableSetupColumn("IP Destino");
                ImGui::TableSetupColumn("Protocolo");
                ImGui::TableSetupColumn("Longitud");
                ImGui::TableHeadersRow();

                std::lock_guard<std::mutex> lock(historial_mutex);
                for (size_t i = 0; i < historial_paquetes.size(); i++) {
                    // Display Filter Logic
                    bool match = true;
                    if (filter_ip_src[0] != '\0' && !contains_icase(historial_paquetes[i].src_ip, filter_ip_src)) match = false;
                    if (filter_ip_dst[0] != '\0' && !contains_icase(historial_paquetes[i].dst_ip, filter_ip_dst)) match = false;
                    if (filter_port_src[0] != '\0' && std::to_string(historial_paquetes[i].src_port) != filter_port_src) match = false;
                    if (filter_port_dst[0] != '\0' && std::to_string(historial_paquetes[i].dst_port) != filter_port_dst) match = false;
                    if (filter_proto_index > 0 && !contains_icase(historial_paquetes[i].protocol_name, proto_options[filter_proto_index])) match = false;
                    
                    if (!match) continue; // Skip rendering

                    ImGui::TableNextRow();
                    
                    ImU32 row_bg_color = IM_COL32(255, 255, 255, 255); // Default Light
                    std::string p_name = historial_paquetes[i].protocol_name;
                    if (p_name == "TCP" || p_name == "HTTP" || p_name == "TLSv1.3") row_bg_color = IM_COL32(231, 230, 255, 255);
                    else if (p_name == "UDP" || p_name == "DNS" || p_name == "SSDP" || p_name == "DHCP") row_bg_color = IM_COL32(218, 238, 255, 255);
                    else if (p_name == "ICMP") row_bg_color = IM_COL32(252, 224, 255, 255);
                    else if (p_name == "ARP") row_bg_color = IM_COL32(250, 240, 215, 255);
                    else if (p_name == "IPv6") row_bg_color = IM_COL32(240, 240, 240, 255);
                    
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, row_bg_color);
                    if (ImGui::TableSetColumnIndex(0)) {
                        char buf[32]; sprintf(buf, "%d", historial_paquetes[i].id);
                        if (ImGui::Selectable(buf, selected_packet_index == (int)i, ImGuiSelectableFlags_SpanAllColumns)) {
                            selected_packet_index = i;
                        }
                    }
                    if (ImGui::TableSetColumnIndex(1)) {
                        char buf[32]; sprintf(buf, "%.6f", historial_paquetes[i].timestamp);
                        ImGui::TextUnformatted(buf);
                    }
                    if (ImGui::TableSetColumnIndex(2)) ImGui::TextUnformatted(historial_paquetes[i].src_ip.c_str());
                    if (ImGui::TableSetColumnIndex(3)) ImGui::TextUnformatted(historial_paquetes[i].dst_ip.c_str());
                    if (ImGui::TableSetColumnIndex(4)) ImGui::TextUnformatted(historial_paquetes[i].protocol_name.c_str());
                    if (ImGui::TableSetColumnIndex(5)) ImGui::Text("%d", historial_paquetes[i].length);
                }

                // Lógica de Auto-Scroll Inteligente
                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 10.0f) {
                    ImGui::SetScrollHereY(1.0f);
                }

                ImGui::EndTable();
            }
            ImGui::PopStyleColor(2); // Restore text color
            ImGui::EndChild();

            // Area 2 & 3: Detalles
            ImGui::BeginChild("Area23", ImVec2(0, area23_h), false);
            
            ImGui::BeginChild("Area2", ImVec2(ImGui::GetContentRegionAvail().x * 0.4f, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            if (selected_packet_index >= 0 && selected_packet_index < (int)historial_paquetes.size()) {
                if (monospace_font) ImGui::PushFont(monospace_font);
                ImGui::TextUnformatted(historial_paquetes[selected_packet_index].detalle.c_str());
                if (monospace_font) ImGui::PopFont();
            }
            ImGui::EndChild();

            ImGui::SameLine();
            ImGui::BeginChild("Area3", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
            if (selected_packet_index >= 0 && selected_packet_index < (int)historial_paquetes.size()) {
                if (monospace_font) ImGui::PushFont(monospace_font);
                render_hex_view(historial_paquetes[selected_packet_index].raw_hex);
                if (monospace_font) ImGui::PopFont();
            } else {
                ImGui::Text("Volcado Hexadecimal...");
            }
            ImGui::EndChild();
            ImGui::EndChild(); // Area23

            // Area 4: Trafico Vulnerable (Fondo del panel izquierdo)
            if (show_vulnerable_tab) {
                ImGui::BeginChild("Area4", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
                ImGui::Text("Trafico Vulnerable (Texto Plano)");
                ImGui::Separator();
                
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 0, 0, 255));
                ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, IM_COL32(255, 180, 180, 255));
                if (ImGui::BeginTable("table_vuln", 7, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("No.");
                    ImGui::TableSetupColumn("Tiempo");
                    ImGui::TableSetupColumn("IP Origen");
                    ImGui::TableSetupColumn("IP Destino");
                    ImGui::TableSetupColumn("Protocolo");
                    ImGui::TableSetupColumn("Longitud");
                    ImGui::TableSetupColumn("Cadena Extraida");
                    ImGui::TableHeadersRow();

                    std::lock_guard<std::mutex> lock(historial_mutex);
                    for (size_t i = 0; i < historial_paquetes.size(); i++) {
                        if (!historial_paquetes[i].is_vulnerable) continue;
                        
                        ImGui::TableNextRow();
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(255, 230, 230, 255));
                        
                        if (ImGui::TableSetColumnIndex(0)) {
                            char buf[32]; sprintf(buf, "%d", historial_paquetes[i].id);
                            if (ImGui::Selectable(buf, selected_packet_index == (int)i, ImGuiSelectableFlags_SpanAllColumns)) {
                                selected_packet_index = i;
                            }
                        }
                        if (ImGui::TableSetColumnIndex(1)) {
                            char buf[32]; sprintf(buf, "%.6f", historial_paquetes[i].timestamp);
                            ImGui::TextUnformatted(buf);
                        }
                        if (ImGui::TableSetColumnIndex(2)) ImGui::TextUnformatted(historial_paquetes[i].src_ip.c_str());
                        if (ImGui::TableSetColumnIndex(3)) ImGui::TextUnformatted(historial_paquetes[i].dst_ip.c_str());
                        if (ImGui::TableSetColumnIndex(4)) ImGui::TextUnformatted(historial_paquetes[i].protocol_name.c_str());
                        if (ImGui::TableSetColumnIndex(5)) ImGui::Text("%d", historial_paquetes[i].length);
                        if (ImGui::TableSetColumnIndex(6)) {
                            std::string snippet = historial_paquetes[i].plain_text_payload;
                            for (char& c : snippet) {
                                if (c == '\n' || c == '\r') c = ' ';
                            }
                            if (snippet.length() > 100) snippet = snippet.substr(0, 100) + "...";
                            ImGui::TextUnformatted(snippet.c_str());
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::PopStyleColor(2);
                ImGui::EndChild();
            }

            ImGui::EndChild(); // LeftPanel
            
            // Right Panel (Graphs)
            if (show_pie_chart || show_io_graph) {
                ImGui::SameLine();
                ImGui::BeginChild("RightPanel", ImVec2(right_panel_width, 0), true);

                if (show_io_graph) {
                    ImGui::Text("Ancho de Banda Utilizado");
                    ImGui::Separator();
                    
                    double current_time = ImGui::GetTime();
                    if (current_time - last_io_time >= 1.0) { // every 1 second
                        unsigned long long current_total = global_stats.total_bytes;
                        unsigned long long diff = 0;
                        if (current_total >= last_total_bytes) diff = current_total - last_total_bytes;
                        else diff = current_total;
                        
                        // shift array
                        for (int i = 0; i < 119; i++) {
                            io_graph_history[i] = io_graph_history[i + 1];
                        }
                        io_graph_history[119] = ((float)diff) / 1024.0f; // KB/s
                        last_total_bytes = current_total;
                        last_io_time = current_time;
                    }
                    
                    auto now = std::chrono::steady_clock::now();
                    std::chrono::duration<double> elapsed = now - capture_start_time;
                    ImGui::g_CaptureElapsedTime = elapsed.count();
                    
                    ImGui::PlotLines("##iograph", io_graph_history, 120, 0, "KB/s", 0.0f, FLT_MAX, ImVec2(right_panel_width - 15, 120));
                    ImGui::Spacing();
                }

                if (show_pie_chart) {
                    ImGui::Text("Distribucion de Protocolos");
                    ImGui::Separator();
                    int total = global_stats.total;
                    if (total > 0) {
                        float data[] = {
                            (float)global_stats.tcp,
                            (float)global_stats.udp,
                            (float)global_stats.icmp,
                            (float)global_stats.arp,
                            (float)global_stats.other
                        };
                        const char* labels[] = { "TCP", "UDP", "ICMP", "ARP", "Otros" };
                        ImU32 colors[] = { 
                            IM_COL32(150, 100, 255, 255), // TCP 
                            IM_COL32(100, 200, 255, 255), // UDP
                            IM_COL32(255, 100, 150, 255), // ICMP
                            IM_COL32(255, 200, 100, 255), // ARP
                            IM_COL32(150, 150, 150, 255)  // Otros
                        };
                        
                        // Render pie chart
                        ImDrawList* draw_list = ImGui::GetWindowDrawList();
                        ImVec2 p = ImGui::GetCursorScreenPos();
                        float radius = 70.0f;
                        ImVec2 center = ImVec2(p.x + right_panel_width / 2.0f - 5, p.y + radius + 10);
                        
                        float a_min = 0.0f;
                        float a_max = 0.0f;
                        for (int i = 0; i < 5; i++) {
                            if (data[i] > 0) {
                                a_max = a_min + (data[i] / total) * (3.1415926535f * 2.0f);
                                draw_list->PathArcTo(center, radius, a_min, a_max, 32);
                                draw_list->PathLineTo(center);
                                draw_list->AddConvexPolyFilled(draw_list->_Path.Data, draw_list->_Path.Size, colors[i]);
                                draw_list->PathClear();
                                a_min = a_max;
                            }
                        }

                        ImGui::Dummy(ImVec2(0, radius * 2 + 20));
                        
                        // Legend
                        for (int i = 0; i < 5; i++) {
                            if (data[i] > 0) {
                                ImGui::PushStyleColor(ImGuiCol_Text, colors[i]);
                                ImGui::Text("%s: %.1f%% (%d)", labels[i], (data[i] / total) * 100.0f, (int)data[i]);
                                ImGui::PopStyleColor();
                            }
                        }
                    } else {
                        ImGui::Text("No hay paquetes capturados.");
                    }
                }
                ImGui::EndChild();
            }
        }

        ImGui::End();
        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.45f, 0.55f, 0.60f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0); 
    }

    detener_captura();
    if (alldevs) pcap_freealldevs(alldevs);

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

// Win32 message handler
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Funciones boilerplate de DirectX11
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}
void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}
void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}
void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}
