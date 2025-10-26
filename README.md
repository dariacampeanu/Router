# Functionalitati principale

1. **Rutare IP pe baza unei tabele statice**
   - Se foloseste un algoritm de tip *Longest Prefix Match* pentru determinarea celei mai bune rute.
   - Tabela este sortata in prealabil pentru a permite cautarea binara.

2. **Gestionarea unei tabele ARP**
   - Pachetele care nu pot fi trimise direct din lipsa unei intrari ARP sunt puse in coada.
   - Se trimit cereri ARP (ARP Request) pentru rezolvarea adresei MAC.
   - Cand se primeste raspunsul ARP, tabela ARP este actualizata, iar pachetele din coada sunt transmise.

3. **Tratarea pachetelor ARP**
   - La primirea unui ARP Request, se construieste si trimite un ARP Reply.
   - La primirea unui ARP Reply, se actualizeaza tabela ARP si se goleste coada de pachete in asteptare.

4. **ICMP**
   - Se trimit pachete ICMP de tip:
     - Echo Reply (raspuns la ping)
     - Time Exceeded (TTL scazut la 0)
     - Destination Unreachable (cand nu exista ruta catre destinatie)
   - ICMP-urile sunt construite manual, la formatul headerelor si calculul checksum-urilor.

5. **Verificarea MAC-ului destinatiei**
   - Pachetele sunt procesate doar daca sunt adresate catre MAC-ul routerului sau sunt de tip broadcast.


# Structura codului

- main(): initializeaza routerul, incarca tabela de rutare si intra in bucla principala de procesare.
- route_comparator(): comparator folosit pentru sortarea tabelei de rutare dupa masca si prefix.
- longest_prefix_match(): functie care aplica algoritmul de cautare binara pentru a gasi cea mai buna ruta.
- get_arp_entry(): cauta o intrare existenta in tabela ARP dupa IP.
- process_arp_request() si process_arp_reply(): gestioneaza pachetele ARP.
- enqueue_packet_for_arp(): pune in coada un pachet care nu poate fi transmis din cauza lipsei unei intrari ARP.
- try_forward_packet(): incearca sa retransmita un pachet IP spre destinatie, folosind ruta si ARP-ul corespunzator.
- handle_icmp_echo_reply(): construieste si trimite un ICMP Echo Reply ca raspuns la un ping.
- build_icmp_error_packet(): construieste pachete ICMP de eroare (folosit de send_icmp_error_packet()).
- buffer_t: structura proprie de coada dinamica pentru retinerea pachetelor in asteptare de ARP.

# Constructia pachetelor ICMP

Se genereaza pachete ICMP manual, incluzand:

- Header Ethernet (cu MAC sursa si destinatie inversate)
- Header IP (cu adrese sursa si destinatie inversate, TTL resetat, checksum recalculat)
- Header ICMP (cu tipul si codul de eroare specificat, plus payload-ul original)


