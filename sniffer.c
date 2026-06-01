
#define HAVE_REMOTE
#include <stdio.h>
#include <stdlib.h>
#include "headers.h"
#include <pcap.h> 

int link_hdr_length = 0;

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    if (packet[12] != 0x08 || packet[13] != 0x00) {
        return; 
    }

    const u_char *ip_ptr = packet + link_hdr_length;
    struct ip_header *ip_hdr = (struct ip_header *)ip_ptr;
    if (ip_hdr->ip_p != 6 && ip_hdr->ip_p != 17) {
        return;
    }

    static int cnt = 1;
    printf("\n Packet %d captured    ", cnt++);

    // ir a donde empieza la ip
    const u_char *ip_packet_ptr = packet + link_hdr_length;
    int ip_hdr_len = (ip_hdr->ip_v_hl & 0x0F) * 4;

    // convertir ips q estan en binario a texto 
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);


    printf("IP Origen: %s   ", src_ip);
    printf("IP Destino: %s   ", dst_ip);
    printf("Protocolo: %d   ", ip_hdr->ip_p);
    // protocolo 6 = TCP, UDP = 17, ICMP = 1 etc

    // si es tcp, calcularel inicio y el tam del payload
    if (ip_hdr->ip_p == 6) {
        const u_char *tcp_packet_ptr = ip_packet_ptr + ip_hdr_len;
        struct tcp_header *tcp_hdr = (struct tcp_header *)tcp_packet_ptr;
        
        int tcp_hdr_len = ((tcp_hdr->th_off_x2 >> 4) & 0x0F) * 4;

        printf("Puerto Origen: %d   ", ntohs(tcp_hdr->th_sport));
        printf("Puerto Destino: %d   ", ntohs(tcp_hdr->th_dport));

        // puntero al inicio de los datos
        const u_char *payload_ptr = tcp_packet_ptr + tcp_hdr_len;
        
        // tam del payload
        int total_ip_len = ntohs(ip_hdr->ip_len);
        int payload_len = total_ip_len - (ip_hdr_len + tcp_hdr_len);

        printf("Tamanioo del Payload: %d bytes     ", payload_len);

        if (payload_len > 0) {
            // mostrar payload en hex

            int limite_bytes = (payload_len > 32) ? 32 : payload_len;

            printf("Payload: ");
            for (int i = 0; i < limite_bytes; i++) {
                printf("%02X ", payload_ptr[i]);
            }

            //mostrar el payload pero ahora en texto legible (no se lee nada pero porque los protocolos son seguros, si fueran inseguros si se podria leer)
            printf("   Payload en texto: ");
            for (int i = 0; i < limite_bytes; i++) {
                if (payload_ptr[i] >= 32 && payload_ptr[i] <= 126) {
                    printf("%c", payload_ptr[i]);
                } else if (payload_ptr[i] == '\n' || payload_ptr[i] == '\r') {
                    printf("%c", payload_ptr[i]); 
                } else {
                    printf("."); 
                }
            }
            printf("\n");
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0); 

    printf("----Packet Sniffer Prueba----\n");

    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_t *capdev;
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    int i=0;
    int numElegido;

    printf("[DEBUG] Llamando a pcap_findalldevs()...\n");
    // 2. Encontrar dispositivos disponibles en Windows
    if (pcap_findalldevs(&alldevs, error_buffer)==-1) {
        printf("Error en pcap_findalldevs: %s\n", error_buffer);
        return 1;
    }

    printf("Tarjetas disponibles(PRUEBA):\n\n");
    for (d=alldevs; d!=NULL; d=d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description)
            printf("Descripcion: %s\n", d->description);
        else
            printf("No encontrado\n");
    }

    //char *device = "enp0s3"; // remember to replace this with your device name 
    //no se si hay una forma de remplazar eso en windows para ahorrarnos todo esto
    if (i==0) {
        printf("Sin interfaces disponibles\n");
        return 1;
    }

    printf("\nIntroduce el numero de la interfaz que quieres usar (1-%d): ", i);
    if (scanf("%d", &numElegido) != 1) {
        printf("Entrada no valida.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    for (d=alldevs, i=1; i<numElegido; d=d->next, i++);

    printf("\nDispositivo: %s\n", d->name);


    capdev = pcap_open_live(d->name, 65536, 1, 1000, error_buffer);
    
    if (capdev == NULL) {
        printf("ERR: pcap_open_live() %s\n", error_buffer);
        pcap_freealldevs(alldevs);
        return 1;
    }

    //asignar valor al link_hrd_type (segun tutorial)
    int link_hdr_type = pcap_datalink(capdev);
    switch (link_hdr_type) {
        case DLT_NULL:
            link_hdr_length = 4;
            break;
        case DLT_EN10MB: 
            link_hdr_length = 14; 
            break;
        default:
            link_hdr_length = 0;
    }


    pcap_freealldevs(alldevs);

    int packets_count=0;

    printf("Escuchando %d paquetes...\n", packets_count);

    if (pcap_loop(capdev, packets_count, call_me, NULL) < 0) {
        printf("ERR: pcap_loop() failed!.\n");
        return 1;
    }

    //esto es para q no se cierre en automatico pq sino no se ve nada
    printf("\nCaptura finalizada con exito.\n");
    pcap_close(capdev);

    printf("\nPresiona ENTER para salir del programa...");
    fflush(stdout);
    getchar(); 
    getchar(); //otro por si acaso
    return 0;
}