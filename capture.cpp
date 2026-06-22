#include <iostream>
#include <vector>
#include <mutex>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap.h>
#include "headers.h"

std::vector<PacketMemory> historial_paquetes;
std::mutex historial_mutex;
ProtocolStats global_stats = {0}; //estadisticas que empiezan en 0

pcap_t *global_capdev = NULL; //Puntero al dispositio activo
int global_link_hdr_length = 0;
volatile bool capture_running = false;
std::thread capture_thread;
std::chrono::steady_clock::time_point capture_start_time;

void generar_hexdump(PacketMemory& pkt, const u_char* packet, int caplen) { //generar hexdump
    //Se encarga de transdormar los bytes crudos en hexadecimal y ascci
    pkt.raw_hex = "Frame " + std::to_string(pkt.id) + ": " + std::to_string(pkt.length) + " bytes on wire\r\n\r\nHEXDUMP (Hex | ASCII):\r\n";
    //Inicializa la cadena de texto con el ID del paquete y su tam real
    char temp[64];

    //Bucle principal: va procesando el paquete en bloques de 16 bytes por fila
    for (int i = 0; i < caplen; i += 16) { //
        sprintf(temp, "%04X  ", i); //imprime el offset
        pkt.raw_hex += temp; 
        for (int j = 0; j < 16; j++) {//Bloque decimal: Imprime los 16 bytes de la fila
            if (i + j < caplen) { //si el byte existe dentro de lo capturado
                sprintf(temp, "%02X ", packet[i + j]);  //espacio de rrelleno por si termino a la mitad
                pkt.raw_hex += temp;
            } else {
                pkt.raw_hex += "   ";
            }
            if (j == 7) pkt.raw_hex += " ";
        }
        pkt.raw_hex += " | ";
        for (int j = 0; j < 16; j++) { //Bloque ASCCI: representa los mismos 16 bytes pero legibles ASCCI
            if (i + j < caplen) {
                u_char c = packet[i + j]; //Si el caracteres imprimible esta dentro de ASCCI
                if (c >= 32 && c <= 126) { //32 a 126
                    pkt.raw_hex += (char)c;
                } else {
                    pkt.raw_hex += "."; //sino son imprimibles es un punto (Caracteres ASCII de control)
                }
            }
        }
        pkt.raw_hex += "\r\n"; //salto de linea para siguiente fila de 16 bytes
    }
}
//DEFINIR 
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!capture_running) return; //sino esta en captura volver

    //calcula segundos transcurridos
    double ts = std::chrono::duration<double>(std::chrono::steady_clock::now() - capture_start_time).count();

    std::lock_guard<std::mutex> lock(historial_mutex); //bloqueo de segyrudad
    global_stats.total_bytes += pkthdr->len; //acumula el peso total de bytes
    
    //Instancia de un objeto temporal para llenar los campos de la interfaz
    PacketMemory pkt;
    pkt.timestamp = ts;
    pkt.length = pkthdr->len;
    pkt.src_ip = "Unknown";
    pkt.dst_ip = "Unknown";
    pkt.src_port = 0;
    pkt.dst_port = 0;
    pkt.protocol_name = "Unknown";
    pkt.is_vulnerable = false;
    pkt.plain_text_payload = "";

    int es_ipv4 = 0;
    const u_char *ip_ptr = NULL; //inicio de la capade red(IP)

    std::string buffer_estructura; //string temporal

    // Ethernet parsing
    if (global_link_hdr_length == 14) { 
        char temp_eth[1024];
        //Extrae las MAC de destino (0-5), de origen (6-11), y EtherType(bytes 12-13)
        sprintf(temp_eth, 
            "=== CAPA DE ENLACE (Ethernet II) ===\r\n"
            "|- MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X\r\n"
            "|- MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X\r\n"
            "|- Tipo: 0x%02X%02X\r\n\r\n",
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
            packet[12], packet[13]);
        buffer_estructura += temp_eth;

        //Revisa cual es el ethertype
        if (packet[12] == 0x08 && packet[13] == 0x00) { // IPv4
            es_ipv4 = 1;
            ip_ptr = packet + 14; //Marcamos la bandera y movemos el puntero ip 14 bytes adelante
        } else if (packet[12] == 0x08 && packet[13] == 0x06) { // ARP
            global_stats.arp++;
            global_stats.total++;
            pkt.protocol_name = "ARP";
            pkt.id = historial_paquetes.size() + 1;
            pkt.src_ip = "MAC";
            pkt.dst_ip = "Broadcast";
            buffer_estructura += "=== CAPA DE RED (ARP) ===\r\n";
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt); //ARP no encapsula IP y salimos 
            return;
        } else if (packet[12] == 0x86 && packet[13] == 0xDD) { // IPv6
            global_stats.other++; 
            global_stats.total++;
            pkt.protocol_name = "IPv6";
            pkt.id = historial_paquetes.size() + 1;
            
            //Mapeamos al formato de IPv6 y se salta 14 bytes de ethernet
            struct ipv6_header *ip6 = (struct ipv6_header *)(packet + 14);
            char src6[INET6_ADDRSTRLEN];
            char dst6[INET6_ADDRSTRLEN];

            //Inet_ntop convierte una cadena binaria de ip a formato legible para humanos
            inet_ntop(AF_INET6, ip6->src, src6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, ip6->dst, dst6, INET6_ADDRSTRLEN);
            pkt.src_ip = src6;
            pkt.dst_ip = dst6;

            //Desenreda campos específicos mediante máscaras de bits y conversion de formato
            int payload_len = ntohs(ip6->payload_len);
            uint32_t vtf = ntohl(ip6->vtf);
            int version = (vtf >> 28) & 0x0F;
            int traffic_class = (vtf >> 20) & 0xFF;
            int flow_label = vtf & 0xFFFFF;

            char sub_ip6[1024];
            sprintf(sub_ip6, "=== CAPA DE RED (IPv6) ===\r\n"
                            "|- Version: %d\r\n"
                            "|- Traffic Class: 0x%02X\r\n"
                            "|- Flow Label: 0x%05X\r\n"
                            "|- Payload Length: %d\r\n"
                            "|- Next Header: %d\r\n"
                            "|- Hop Limit: %d\r\n", 
                            version, traffic_class, flow_label, payload_len, ip6->next_header, ip6->hop_limit);
            buffer_estructura += sub_ip6;

            const u_char* payload_ptr = packet + 14 + 40; // 40 ies estandar para IPv6 header TAM
            
            //subprotocolo en ipv6 
            if (ip6->next_header == 6) { // TCP
                global_stats.other--; global_stats.tcp++;
                pkt.protocol_name = "TCP";
                struct tcp_header *tcp_hdr = (struct tcp_header *)payload_ptr;
                uint16_t sport = ntohs(tcp_hdr->th_sport);
                uint16_t dport = ntohs(tcp_hdr->th_dport);
                pkt.src_port = sport; pkt.dst_port = dport;

                //clasificacion básica por puetos conocidos
                if (sport == 443 || dport == 443) pkt.protocol_name = "TLSv1.3";
                else if (sport == 80 || dport == 80) pkt.protocol_name = "HTTP";
                char sub_tcp[512];
                sprintf(sub_tcp, "\r\n=== CAPA DE TRANSPORTE (TCP) ===\r\n|- Puerto Origen: %d\r\n|- Puerto Destino: %d\r\n|- Numero Secuencia: %u\r\n|- Numero ACK: %u\r\n", sport, dport, ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
                buffer_estructura += sub_tcp;
                
                if (sport == 21 || dport == 21) buffer_estructura += "|- Aplicacion: FTP\r\n";
                else if (sport == 23 || dport == 23) buffer_estructura += "|- Aplicacion: Telnet\r\n";

                //Extraccion de texto plano e identificacion de vulnerabulidades (HTTP, Telnet)
                if (sport == 80 || dport == 80 || sport == 21 || dport == 21 || sport == 23 || dport == 23) {
                    int tcp_hdr_len = (tcp_hdr->th_off_x2 >> 4) * 4;
                    int payload_offset = 40 + tcp_hdr_len;
                    int p_len = payload_len - tcp_hdr_len;
                    if (p_len > 0) {
                        const u_char* payload_data = packet + 14 + 40 + tcp_hdr_len;
                        buffer_estructura += "\r\n[PAYLOAD EXTRAIDO]\r\n";
                        //Ciclo que extrae los caracteres y los pasa a texto plano
                        for (int i = 0; i < p_len && (14 + 40 + tcp_hdr_len + i) < (int)pkthdr->caplen; i++) {
                            u_char c = payload_data[i];
                            if (c >= 32 && c <= 126) { pkt.plain_text_payload += (char)c; buffer_estructura += (char)c; }
                            else if (c == '\n' || c == '\r') { pkt.plain_text_payload += (char)c; buffer_estructura += (char)c; }
                            else { pkt.plain_text_payload += "."; buffer_estructura += "."; }
                        }
                        
                        // Smart detection: only flag as vulnerable if actual plaintext commands are found,
                        // o si es protocolo Telnet (23) o FTP (21) ya que estos siempre son de texto plano.
                        if (sport == 21 || dport == 21 || sport == 23 || dport == 23 ||
                            pkt.plain_text_payload.find("HTTP") != std::string::npos ||
                            pkt.plain_text_payload.find("GET ") != std::string::npos ||
                            pkt.plain_text_payload.find("POST ") != std::string::npos ||
                            pkt.plain_text_payload.find("USER ") != std::string::npos ||
                            pkt.plain_text_payload.find("PASS ") != std::string::npos) {
                            
                            pkt.is_vulnerable = true;
                        }
                    }
                }
            } else if (ip6->next_header == 17) { // UDP
                global_stats.other--; global_stats.udp++;
                pkt.protocol_name = "UDP";
                uint16_t sport = ntohs(*(uint16_t *)(payload_ptr));
                uint16_t dport = ntohs(*(uint16_t *)(payload_ptr + 2));
                pkt.src_port = sport; pkt.dst_port = dport;
                if (sport == 53 || dport == 53) pkt.protocol_name = "DNS";
                else if (sport == 1900 || dport == 1900) pkt.protocol_name = "SSDP";
                char sub_udp[512];
                sprintf(sub_udp, "\r\n=== CAPA DE TRANSPORTE (UDP) ===\r\n|- Puerto Origen: %d\r\n|- Puerto Destino: %d\r\n", sport, dport);
                buffer_estructura += sub_udp;
            } else if (ip6->next_header == 58) { // ICMPv6
                global_stats.other--; global_stats.icmp++;
                pkt.protocol_name = "ICMPv6";
                buffer_estructura += "\r\n=== CAPA DE RED (ICMPv6) ===\r\n";
            }
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt);
            return;
        } else {
            //No coincide con Ipv6, ni IPb4 ni ARP se consifera fenerico
            global_stats.other++;
            global_stats.total++;
            pkt.protocol_name = "Ethernet";
            pkt.id = historial_paquetes.size() + 1;
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt);
            return;
        }
    } else if (global_link_hdr_length == 4) { //caso especial de adapadores NULL o Loopback en lugar de ethernet
        if (packet[0] == 2 || packet[0] == 24 || packet[2] == 0x08) {
            es_ipv4 = 1;
            ip_ptr = packet + 4;
        }
    }

    if (!es_ipv4 || !ip_ptr) return; //si traes ecaluar las capas de enlace NO tiene trafico

    struct ip_header *ip_hdr = (struct ip_header *)ip_ptr;
    
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst, INET_ADDRSTRLEN);
    pkt.src_ip = src;
    pkt.dst_ip = dst;

    int ip_hdr_len = (ip_hdr->ip_v_hl & 0x0F) * 4;

    char sub_ipv4[1024];
    sprintf(sub_ipv4, "=== CAPA DE RED (IPv4) ===\r\n"
                    "|- Longitud Total: %d\r\n"
                    "|- TTL: %d\r\n"
                    "|- Protocolo Interno: %d\r\n", 
                    ntohs(ip_hdr->ip_len), ip_hdr->ip_ttl, ip_hdr->ip_p);
    buffer_estructura += sub_ipv4;

    //Transporte en Ipv6 
    if (ip_hdr->ip_p == 6) { //protocolo tco
        global_stats.tcp++;
        pkt.protocol_name = "TCP";

        //mueve el puntero para saltarse el encambezado IP dinámico
        const u_char *tcp_packet_ptr = ip_ptr + ip_hdr_len;
        struct tcp_header *tcp_hdr = (struct tcp_header *)tcp_packet_ptr;

        uint16_t sport = ntohs(tcp_hdr->th_sport);
        uint16_t dport = ntohs(tcp_hdr->th_dport);
        pkt.src_port = sport;
        pkt.dst_port = dport;

        if (sport == 443 || dport == 443) pkt.protocol_name = "TLSv1.3";
        else if (sport == 80 || dport == 80) pkt.protocol_name = "HTTP";

        char sub_tcp[512];
        sprintf(sub_tcp, 
                "\r\n=== CAPA DE TRANSPORTE (TCP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n"
                "|- Numero Secuencia: %u\r\n"
                "|- Numero ACK: %u\r\n", 
                sport, dport, ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
        buffer_estructura += sub_tcp;
        
        if (sport == 21 || dport == 21) buffer_estructura += "|- Aplicacion: FTP\r\n";
        else if (sport == 23 || dport == 23) buffer_estructura += "|- Aplicacion: Telnet\r\n";

        //ANALIZADOR DE TEXTO PLANO 
        if (sport == 80 || dport == 80 || sport == 21 || dport == 21 || sport == 23 || dport == 23) {
            // Extract Payload
            int tcp_hdr_len = (tcp_hdr->th_off_x2 >> 4) * 4;
            int payload_offset = ip_hdr_len + tcp_hdr_len;
            int payload_len = ntohs(ip_hdr->ip_len) - payload_offset;
            if (payload_len > 0) {
                const u_char* payload_ptr = ip_ptr + payload_offset;
                buffer_estructura += "\r\n[PAYLOAD EXTRAIDO]\r\n";
                for (int i = 0; i < payload_len; i++) {
                    u_char c = payload_ptr[i];
                    if (c >= 32 && c <= 126) { pkt.plain_text_payload += (char)c; buffer_estructura += (char)c; }
                    else if (c == '\n' || c == '\r') { pkt.plain_text_payload += (char)c; buffer_estructura += (char)c; }
                    else { pkt.plain_text_payload += "."; buffer_estructura += "."; }
                }
                
                // Smart detection: only flag as vulnerable if actual plaintext commands are found,
                // o si es protocolo Telnet (23) o FTP (21) ya que estos siempre son de texto plano.
                if (sport == 21 || dport == 21 || sport == 23 || dport == 23 ||
                    pkt.plain_text_payload.find("HTTP") != std::string::npos ||
                    pkt.plain_text_payload.find("GET ") != std::string::npos ||
                    pkt.plain_text_payload.find("POST ") != std::string::npos ||
                    pkt.plain_text_payload.find("USER ") != std::string::npos ||
                    pkt.plain_text_payload.find("PASS ") != std::string::npos) {
                    
                    pkt.is_vulnerable = true;
                }
            }
        }
        
    } else if (ip_hdr->ip_p == 17) { //Protocolo UDP
        global_stats.udp++;
        pkt.protocol_name = "UDP";
        const u_char *udp_packet_ptr = ip_ptr + ip_hdr_len;
        uint16_t sport = ntohs(*(uint16_t *)(udp_packet_ptr));
        uint16_t dport = ntohs(*(uint16_t *)(udp_packet_ptr + 2));
        pkt.src_port = sport;
        pkt.dst_port = dport;
        
        //Mapeo crudo de puertos en memoria
        if (sport == 53 || dport == 53) pkt.protocol_name = "DNS";
        else if (sport == 1900 || dport == 1900) pkt.protocol_name = "SSDP";
        else if (sport == 67 || dport == 68 || sport == 68 || dport == 67) pkt.protocol_name = "DHCP";

        char sub_udp[512];
        sprintf(sub_udp, 
                "\r\n=== CAPA DE TRANSPORTE (UDP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n", sport, dport);
        buffer_estructura += sub_udp;
    } else if (ip_hdr->ip_p == 1) {
            pkt.protocol_name = "ICMP";
            global_stats.icmp++;
            
            // Extraer ICMP info básica
            int ip_len = (ip_hdr->ip_v_hl & 0x0F) * 4;
            const u_char* icmp_header = (const u_char*)ip_hdr + ip_len;
            if (pkthdr->caplen >= 14 + ip_len + 2) {
                int type = icmp_header[0];
                int code = icmp_header[1];
                char sub_icmp[128];
                snprintf(sub_icmp, sizeof(sub_icmp), "=== CAPA DE RED (ICMP) ===\r\n| - Tipo: %d\r\n| - Codigo: %d\r\n", type, code);
                buffer_estructura += sub_icmp;
            }
    } else {
            pkt.protocol_name = "IPv4 (Otro)";
            global_stats.other++;
    }

    //Almacenamiento final
    global_stats.total++;

    pkt.id = historial_paquetes.size() + 1; //Asigna un numero mas
    pkt.detalle = buffer_estructura; //Añade el paquete

    generar_hexdump(pkt, packet, pkthdr->caplen);

    historial_paquetes.push_back(pkt);
}

void HiloCaptura() {
    if (global_capdev) {
        pcap_loop(global_capdev, 0, call_me, NULL);
    }
}

void iniciar_captura(pcap_t *dev, int link_len) {
    if (capture_running) return; //revisa si esta corriendo 
    global_capdev = dev; //
    global_link_hdr_length = link_len;
    capture_start_time = std::chrono::steady_clock::now();
    capture_running = true;
    capture_thread = std::thread(HiloCaptura);//llama al hilo
}

void detener_captura() {
    capture_running = false;
    if (global_capdev) {
        pcap_breakloop(global_capdev);
    }
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
    if (global_capdev) {
        pcap_close(global_capdev);
        global_capdev = NULL;
    }
}

// Ya no lo usaremos como filtro de captura (BPF), sino visual. Retornamos 1 siempre.
int aplicar_filtro(const char* filter_exp) {
    return 1; 
}
