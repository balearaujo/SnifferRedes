#ifndef HEADERS_H
#define HEADERS_H

#define HAVE_REMOTE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

struct ip_header {
    u_char  ip_hl:4, ip_v:4; // cabezera y version
    u_char  ip_tos;          // typee of service
    u_short ip_len;          // longitud
    u_short ip_id;           // id del paquete
    u_short ip_off;          // fragmentacion n del paquete
    u_char  ip_ttl;          // tiempo de vida del paquete
    u_char  ip_p;            // protocolo del paq quete
    u_short ip_sum;          // checksum (es para verfiicar la integridad de los datos creo)
    struct  in_addr ip_src;  // ip origen
    struct  in_addr ip_dst;  // ip destino
};

struct tcp_header {          // para tcp
    u_short th_sport;        // puerto origen
    u_short th_dport;        // puerto destino
    u_int   th_seq;          // num secuencia
    u_int   th_ack;          // num ACK
    u_char  th_off:4, th_x2:4; // offset de Data ( multi *4 da el tamaño de la cabecera)
    u_char  th_flags;        // flags 
    u_short th_win;          
    u_short th_sum;          
    u_short th_urp;
    // se pueden agregar mas campos si ocupamos analizar mas banderas o cosas asi
};



#endif