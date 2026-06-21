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

//contadores de estadisticas
typedef struct {
    int tcp;
    int udp;
    int icmp;
    int arp;
    int other;
    int total;
    unsigned long long total_bytes;
} ProtocolStats;

extern ProtocolStats global_stats;

#ifdef __cplusplus
#include <vector>
#include <mutex>
#include <string>

struct PacketMemory { //registro completo de cada paquete
    int id; //id
    double timestamp; //segundo en q se capturo
    std::string src_ip; //src ip
    std::string dst_ip;
    std::string protocol_name; //nombre del protocolo
    int src_port;
    int dst_port;
    int length; //tamaño total del paquete medido en bytes
    std::string detalle; //Textodecodificado de las cabeceras
    std::string raw_hex; //Contiene la cadena de texto con Hexdump exacto
    bool is_vulnerable; //Usa una bandera de verdadero/falso
    std::string plain_text_payload; //si el paquete es vulnerable se guarda el texto
};

extern std::vector<PacketMemory> historial_paquetes; //arreglo dinamico donde se guarda
extern std::mutex historial_mutex; //mutex es un cerrojo de seguridad, para que los hilos no
//accedan al mismo tiempo

#else
extern int total_paquetes;
#endif

// Funciones expuestas
void iniciar_captura(pcap_t *dev, int link_len);
void detener_captura();
void exportar_csv();
int aplicar_filtro(const char* filter_exp);

#endif