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
ProtocolStats global_stats = {0};

pcap_t *global_capdev = NULL;
int global_link_hdr_length = 0;
volatile bool capture_running = false;
std::thread capture_thread;
std::chrono::steady_clock::time_point capture_start_time;

void generar_hexdump(PacketMemory& pkt, const u_char* packet, int caplen) {
    pkt.raw_hex = "Frame " + std::to_string(pkt.id) + ": " + std::to_string(pkt.length) + " bytes on wire\r\n\r\nHEXDUMP (Hex | ASCII):\r\n";
    char temp[64];
    for (int i = 0; i < caplen; i += 16) {
        sprintf(temp, "%04X  ", i);
        pkt.raw_hex += temp;
        for (int j = 0; j < 16; j++) {
            if (i + j < caplen) {
                sprintf(temp, "%02X ", packet[i + j]);
                pkt.raw_hex += temp;
            } else {
                pkt.raw_hex += "   ";
            }
            if (j == 7) pkt.raw_hex += " ";
        }
        pkt.raw_hex += " | ";
        for (int j = 0; j < 16; j++) {
            if (i + j < caplen) {
                u_char c = packet[i + j];
                if (c >= 32 && c <= 126) {
                    pkt.raw_hex += (char)c;
                } else {
                    pkt.raw_hex += ".";
                }
            }
        }
        pkt.raw_hex += "\r\n";
    }
}

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!capture_running) return;

    double ts = std::chrono::duration<double>(std::chrono::steady_clock::now() - capture_start_time).count();

    std::lock_guard<std::mutex> lock(historial_mutex);
    global_stats.total_bytes += pkthdr->len;
    
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
    const u_char *ip_ptr = NULL;

    char buffer_estructura[2048] = {0};

    // Ethernet parsing
    if (global_link_hdr_length == 14) { 
        sprintf(buffer_estructura, 
            "=== CAPA DE ENLACE (Ethernet II) ===\r\n"
            "|- MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X\r\n"
            "|- MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X\r\n"
            "|- Tipo: 0x%02X%02X\r\n\r\n",
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
            packet[12], packet[13]);

        if (packet[12] == 0x08 && packet[13] == 0x00) { // IPv4
            es_ipv4 = 1;
            ip_ptr = packet + 14;
        } else if (packet[12] == 0x08 && packet[13] == 0x06) { // ARP
            global_stats.arp++;
            global_stats.total++;
            pkt.protocol_name = "ARP";
            pkt.id = historial_paquetes.size() + 1;
            pkt.src_ip = "MAC";
            pkt.dst_ip = "Broadcast";
            strcat(buffer_estructura, "=== CAPA DE RED (ARP) ===\r\n");
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt);
            return;
        } else if (packet[12] == 0x86 && packet[13] == 0xDD) { // IPv6
            global_stats.other++; 
            global_stats.total++;
            pkt.protocol_name = "IPv6";
            pkt.id = historial_paquetes.size() + 1;
            
            struct ipv6_header *ip6 = (struct ipv6_header *)(packet + 14);
            char src6[INET6_ADDRSTRLEN];
            char dst6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip6->src, src6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, ip6->dst, dst6, INET6_ADDRSTRLEN);
            pkt.src_ip = src6;
            pkt.dst_ip = dst6;

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
            strcat(buffer_estructura, sub_ip6);

            const u_char* payload_ptr = packet + 14 + 40; // 40 ies estandar para IPv6 header TAM
            
            if (ip6->next_header == 6) { // TCP
                global_stats.other--; global_stats.tcp++;
                pkt.protocol_name = "TCP";
                struct tcp_header *tcp_hdr = (struct tcp_header *)payload_ptr;
                uint16_t sport = ntohs(tcp_hdr->th_sport);
                uint16_t dport = ntohs(tcp_hdr->th_dport);
                pkt.src_port = sport; pkt.dst_port = dport;
                if (sport == 443 || dport == 443) pkt.protocol_name = "TLSv1.3";
                else if (sport == 80 || dport == 80) pkt.protocol_name = "HTTP";
                char sub_tcp[512];
                sprintf(sub_tcp, "\r\n=== CAPA DE TRANSPORTE (TCP) ===\r\n|- Puerto Origen: %d\r\n|- Puerto Destino: %d\r\n|- Numero Secuencia: %u\r\n|- Numero ACK: %u\r\n", sport, dport, ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
                strcat(buffer_estructura, sub_tcp);

                if (sport == 80 || dport == 80 || sport == 21 || dport == 21 || sport == 23 || dport == 23) {
                    strcat(buffer_estructura, "\r\n[!] ADVERTENCIA: TRAFICO VULNERABLE (Texto Plano Detectado) [!]\r\n");
                    pkt.is_vulnerable = true;
                    
                    int tcp_hdr_len = (tcp_hdr->th_off_x2 >> 4) * 4;
                    int payload_offset = 40 + tcp_hdr_len;
                    int p_len = payload_len - tcp_hdr_len;
                    if (p_len > 0) {
                        const u_char* payload_data = packet + 14 + 40 + tcp_hdr_len;
                        strcat(buffer_estructura, "\r\n[PAYLOAD EXTRAIDO]\r\n");
                        char temp_str[2] = {0};
                        for (int i = 0; i < p_len && (14 + 40 + tcp_hdr_len + i) < (int)pkthdr->caplen; i++) {
                            u_char c = payload_data[i];
                            if (c >= 32 && c <= 126) { pkt.plain_text_payload += (char)c; temp_str[0] = (char)c; strcat(buffer_estructura, temp_str); }
                            else if (c == '\n' || c == '\r') { pkt.plain_text_payload += (char)c; temp_str[0] = (char)c; strcat(buffer_estructura, temp_str); }
                            else { pkt.plain_text_payload += "."; strcat(buffer_estructura, "."); }
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
                strcat(buffer_estructura, sub_udp);
            } else if (ip6->next_header == 58) { // ICMPv6
                global_stats.other--; global_stats.icmp++;
                pkt.protocol_name = "ICMPv6";
                strcat(buffer_estructura, "\r\n=== CAPA DE RED (ICMPv6) ===\r\n");
            }
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt);
            return;
        } else {
            global_stats.other++;
            global_stats.total++;
            pkt.protocol_name = "Ethernet";
            pkt.id = historial_paquetes.size() + 1;
            pkt.detalle = buffer_estructura;
            generar_hexdump(pkt, packet, pkthdr->caplen);
            historial_paquetes.push_back(pkt);
            return;
        }
    } else if (global_link_hdr_length == 4) { 
        if (packet[0] == 2 || packet[0] == 24 || packet[2] == 0x08) {
            es_ipv4 = 1;
            ip_ptr = packet + 4;
        }
    }

    if (!es_ipv4 || !ip_ptr) return;

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
    strcat(buffer_estructura, sub_ipv4);

    if (ip_hdr->ip_p == 6) { 
        global_stats.tcp++;
        pkt.protocol_name = "TCP";
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
        strcat(buffer_estructura, sub_tcp);

        if (sport == 80 || dport == 80 || sport == 21 || dport == 21 || sport == 23 || dport == 23) {
            pkt.is_vulnerable = true;
            
            // Extract Payload
            int tcp_hdr_len = (tcp_hdr->th_off_x2 >> 4) * 4;
            int payload_offset = ip_hdr_len + tcp_hdr_len;
            int payload_len = ntohs(ip_hdr->ip_len) - payload_offset;
            if (payload_len > 0) {
                const u_char* payload_ptr = ip_ptr + payload_offset;
                strcat(buffer_estructura, "\r\n[PAYLOAD EXTRAIDO]\r\n");
                char temp_str[2] = {0};
                for (int i = 0; i < payload_len; i++) {
                    u_char c = payload_ptr[i];
                    if (c >= 32 && c <= 126) { pkt.plain_text_payload += (char)c; temp_str[0] = (char)c; strcat(buffer_estructura, temp_str); }
                    else if (c == '\n' || c == '\r') { pkt.plain_text_payload += (char)c; temp_str[0] = (char)c; strcat(buffer_estructura, temp_str); }
                    else { pkt.plain_text_payload += "."; strcat(buffer_estructura, "."); }
                }
            }
        }
        
    } else if (ip_hdr->ip_p == 17) { 
        global_stats.udp++;
        pkt.protocol_name = "UDP";
        const u_char *udp_packet_ptr = ip_ptr + ip_hdr_len;
        uint16_t sport = ntohs(*(uint16_t *)(udp_packet_ptr));
        uint16_t dport = ntohs(*(uint16_t *)(udp_packet_ptr + 2));
        pkt.src_port = sport;
        pkt.dst_port = dport;
        
        if (sport == 53 || dport == 53) pkt.protocol_name = "DNS";
        else if (sport == 1900 || dport == 1900) pkt.protocol_name = "SSDP";
        else if (sport == 67 || dport == 68 || sport == 68 || dport == 67) pkt.protocol_name = "DHCP";

        char sub_udp[512];
        sprintf(sub_udp, 
                "\r\n=== CAPA DE TRANSPORTE (UDP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n", sport, dport);
        strcat(buffer_estructura, sub_udp);
    } else if (ip_hdr->ip_p == 1) { 
        global_stats.icmp++;
        pkt.protocol_name = "ICMP";
        strcat(buffer_estructura, "\r\n=== CAPA DE RED (ICMP) ===\r\n");
    } else {
        global_stats.other++;
        pkt.protocol_name = "IPv4 (Other)";
    }

    global_stats.total++;

    pkt.id = historial_paquetes.size() + 1;
    pkt.detalle = buffer_estructura;

    generar_hexdump(pkt, packet, pkthdr->caplen);

    historial_paquetes.push_back(pkt);
}

void HiloCaptura() {
    if (global_capdev) {
        pcap_loop(global_capdev, 0, call_me, NULL);
    }
}

void iniciar_captura(pcap_t *dev, int link_len) {
    if (capture_running) return;
    global_capdev = dev;
    global_link_hdr_length = link_len;
    capture_start_time = std::chrono::steady_clock::now();
    capture_running = true;
    capture_thread = std::thread(HiloCaptura);
}

void detener_captura() {
    if (!capture_running) return;
    capture_running = false;
    if (global_capdev) {
        pcap_breakloop(global_capdev);
    }
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
}

// Ya no lo usaremos como filtro de captura (BPF), sino visual. Retornamos 1 siempre.
int aplicar_filtro(const char* filter_exp) {
    return 1; 
}
