#include <iostream>
#include <vector>
#include <mutex>
#include <thread>
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

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!capture_running) return;

    int es_ipv4 = 0;
    const u_char *ip_ptr = NULL;

    if (global_link_hdr_length == 14) { 
        if (packet[12] == 0x08 && packet[13] == 0x00) {
            es_ipv4 = 1;
            ip_ptr = packet + 14;
        } else if (packet[12] == 0x08 && packet[13] == 0x06) {
            std::lock_guard<std::mutex> lock(historial_mutex);
            global_stats.arp++;
            global_stats.total++;
            return;
        } else if (packet[12] == 0x86 && packet[13] == 0xDD) {
            std::lock_guard<std::mutex> lock(historial_mutex);
            global_stats.other++; 
            global_stats.total++;
            return;
        } else {
            std::lock_guard<std::mutex> lock(historial_mutex);
            global_stats.other++;
            global_stats.total++;
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
    PacketMemory pkt = {0};
    
    pkt.length = pkthdr->len;
    pkt.protocol = ip_hdr->ip_p;

    inet_ntop(AF_INET, &(ip_hdr->ip_src), pkt.src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), pkt.dst_ip, INET_ADDRSTRLEN);

    int ip_hdr_len = (ip_hdr->ip_v_hl & 0x0F) * 4;
    char buffer_estructura[1024] = {0};
    char buffer_hex[2048] = {0};

    sprintf(buffer_estructura, 
            "=== CAPA DE RED (IPv4) ===\r\n"
            "|- Version: %d\r\n"
            "|- Tamano Cabecera: %d bytes\r\n"
            "|- TTL: %d\r\n"
            "|- Protocolo: %d\r\n", 
            (ip_hdr->ip_v_hl >> 4), ip_hdr_len, ip_hdr->ip_ttl, ip_hdr->ip_p);

    std::lock_guard<std::mutex> lock(historial_mutex);

    if (ip_hdr->ip_p == 6) { 
        global_stats.tcp++;
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
            strcpy(buffer_hex, "[Paquete TCP vacio]");
        }
    } else if (ip_hdr->ip_p == 17) { 
        global_stats.udp++;
        const u_char *udp_packet_ptr = ip_ptr + ip_hdr_len;
        uint16_t sport = ntohs(*(uint16_t *)(udp_packet_ptr));
        uint16_t dport = ntohs(*(uint16_t *)(udp_packet_ptr + 2));
        
        char sub_udp[512];
        sprintf(sub_udp, 
                "\r\n=== CAPA DE TRANSPORTE (UDP) ===\r\n"
                "|- Puerto Origen: %d\r\n"
                "|- Puerto Destino: %d\r\n", sport, dport);
        strcat(buffer_estructura, sub_udp);
        strcpy(buffer_hex, "[Datos UDP]");
    } else if (ip_hdr->ip_p == 1) { 
        global_stats.icmp++;
        strcat(buffer_estructura, "\r\n=== CAPA DE RED (ICMP) ===\r\n");
        strcpy(buffer_hex, "[Datos ICMP]");
    } else {
        global_stats.other++;
    }

    global_stats.total++;

    pkt.id = historial_paquetes.size() + 1;
    strcpy(pkt.detalle, buffer_estructura);
    strcpy(pkt.raw_hex, buffer_hex);

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

int aplicar_filtro(const char* filter_exp) {
    if (!global_capdev) return 0;
    struct bpf_program fcode;
    bpf_u_int32 netmask = 0xffffff;
    if (pcap_compile(global_capdev, &fcode, filter_exp, 1, netmask) < 0) {
        return 0;
    }
    if (pcap_setfilter(global_capdev, &fcode) < 0) {
        return 0; 
    }
    return 1; 
}
