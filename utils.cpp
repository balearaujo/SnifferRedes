#include <stdio.h>
#include <windows.h>
#include "headers.h"

void exportar_csv() {
    std::lock_guard<std::mutex> lock(historial_mutex);
    if (historial_paquetes.empty()) {
        MessageBoxA(NULL, "No hay paquetes para exportar.", "Aviso", MB_ICONINFORMATION);
        return;
    }

    OPENFILENAMEA ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "CSV (Delimitado por comas)\0*.csv\0Todos los archivos\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrDefExt = "csv";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameA(&ofn) == TRUE) {
        FILE *fp = fopen(ofn.lpstrFile, "w");
        if (fp != NULL) {
            fprintf(fp, "No.,Tiempo,IP Origen,IP Destino,Protocolo,Longitud\n");
            for (size_t i = 0; i < historial_paquetes.size(); i++) {
                fprintf(fp, "%d,%.6f,%s,%s,%s,%d\n",
                        historial_paquetes[i].id,
                        historial_paquetes[i].timestamp,
                        historial_paquetes[i].src_ip.c_str(),
                        historial_paquetes[i].dst_ip.c_str(),
                        historial_paquetes[i].protocol_name.c_str(),
                        historial_paquetes[i].length);
            }
            fclose(fp);
            MessageBoxA(NULL, "Exportacion completada con exito.", "Exito", MB_ICONINFORMATION);
        } else {
            MessageBoxA(NULL, "Error al guardar el archivo CSV.", "Error", MB_ICONERROR);
        }
    }
}
