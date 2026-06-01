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



#endif