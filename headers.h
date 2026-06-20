#ifndef HEADERS_H
#define HEADERS_H

#define HAVE_REMOTE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <stdint.h>

struct ip_header {
    uint8_t  ip_v_hl; // cabezera y version
    uint8_t  ip_tos;          // typee of service
    uint16_t ip_len;          // longitud
    uint16_t ip_id;           // id del paquete
    uint16_t ip_off;          // fragmentacion n del paquete
    uint8_t  ip_ttl;          // tiempo de vida del paquete
    uint8_t  ip_p;            // protocolo del paq quete
    uint16_t ip_sum;          // checksum (es para verfiicar la integridad de los datos creo)
    struct  in_addr ip_src;  // ip origen
    struct  in_addr ip_dst;  // ip destino
} __attribute__((packed));

struct tcp_header {          // para tcp
    uint16_t th_sport;        // puerto origen
    uint16_t th_dport;        // puerto destino
    uint32_t   th_seq;          // num secuencia
    uint32_t   th_ack;          // num ACK
    uint8_t  th_off_x2; // offset de Data ( multi *4 da el tamaño de la cabecera)
    uint8_t  th_flags;        // flags 
    uint16_t th_win;          
    uint16_t th_sum;          
    uint16_t th_urp;
    // se pueden agregar mas campos si ocupamos analizar mas banderas o cosas asi
} __attribute__((packed));

struct udp_header {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
} __attribute__((packed));

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed));

struct ipv6_header {
    uint32_t vtf; // version, traffic class, flow label
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
} __attribute__((packed));

typedef struct {
    int tcp;
    int udp;
    int icmp;
    int arp;
    int other;
    int total;
} ProtocolStats;

extern ProtocolStats global_stats;

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

#define MAX_PACKETS 10000

#ifdef __cplusplus
#include <vector>
#include <mutex>
#include <string>

extern std::vector<PacketMemory> historial_paquetes;
extern std::mutex historial_mutex;

#else
extern PacketMemory historial_paquetes[MAX_PACKETS];
extern int total_paquetes;
#endif

// Funciones expuestas
void iniciar_captura(pcap_t *dev, int link_len);
void detener_captura();
void exportar_csv();
int aplicar_filtro(const char* filter_exp);

#ifdef __cplusplus
extern "C" {
#endif
pcap_t* MostrarSelectorInterfaces(void* hInstance, int *out_link_length);
#ifdef __cplusplus
}
#endif

#endif