#include <stdio.h>
#include <stdlib.h>

#define HAVE_REMOTE
#include <stdio.h>
#include <stdlib.h>

#define HAVE_REMOTE
#include <pcap.h> 

void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int cnt=1;
    printf("Paquete: %d capturado. Tamano: %d bytes\n", cnt++, pkthdr->len);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0); 

    printf("----Packet Sniffer Prueba----\n");

    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_t *capdev;
    char error_buffer[PCAP_ERRBUF_SIZE];
    int packets_count=20;
    
    int i=0;
    int numElegido;

    printf("[DEBUG] Llamando a pcap_findalldevs()...\n");
    //Encontrar dispositivos disponibles en Windows
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

    //char *device = "enp0s3"; 
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


    capdev = pcap_open_live(d->name, 65536, 1, 1000, error_buffer); //no se si dejarlo en 1 o 0
    
    if (capdev == NULL) {
        printf("ERR: pcap_open_live() %s\n", error_buffer);
        pcap_freealldevs(alldevs);
        return 1;
    }
    pcap_freealldevs(alldevs);

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
    getchar(); //otro porq no sirve
    return 0;
}