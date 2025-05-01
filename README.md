# Evaluierung der Fehlerkorrektur und authentifizierten Verschlüsselung des MAGIC-Modus auf einem Mikrocontroller mit externem Speicher

## Allgemeines
Mit dieser Arbeit handelt es sich um meine Bachelorarbeit an der Hochschule RheinMain. Dazu wurde eine Implementierung des MAGIC-Modus erstellt und mit dem Hamming-Code bezüglich der Fehlerkorrektur verglichen. Dazu wurden die Takte auf einem Mikrocontroller mit externen SRAM gemessen. Dabei handelt es sich um das ChipSHOUTER® CW521 Ballistic Gel Board. Die Messergebnisse befinden sich im Ordner ``evaluation``. Die PDF-Datei dieser Arbeit befindet sich im Hauptordner von diesem Projekt. Darin werden unter anderem die jeweiligen Programmteile genauer erläutert.

## Abstract
### Deutsch
Das Ziel dieser Bachelorarbeit ist es herauszufinden, wie gut der MAGIC-Modus auf einem eingebetteten System funktioniert. Dazu wurde MAGIC selbst implementiert und mit dem Hamming-Code verglichen. Für die Evaluierung werden die Taktzyklen und der Speicherverbrauch auf dem eingebetteten System betrachtet. Die Evaluierungsergebnisse zeigen, dass der Hamming-Code in Bezug auf die Fehlerkorrektur deutlich schneller ist, aber mindestens 128 Bits zusätzlichen Speicher dafür benötigt. Jedoch kann der MAGIC-Modus in der Theorie mehr Fehler erkennen und korrigieren als der Hamming-Code. Dies zeigt, dass man nach aktuellem Stand in der Regel weiterhin den Hamming-Code verwenden sollte. Nur wenn die Speicherkapazität und eine geringere Komplexität eine sehr hohe Priorität haben, sollte man den MAGIC-Modus auf einem eingebetteten System einsetzen.

### English
The aim of this bachelor’s thesis is to find out how well the MAGIC mode works on an embedded system. For this purpose, it was implemented and compared with the Hamming code. For the evaluation, the clock cycles and the memory consumption on the embedded system were analysed. The evaluation results show that the Hamming code is significantly faster in terms of error correction, but requires at least 128 bits of additional memory. However, the MAGIC mode in theory can recognise and correct more errors than the Hamming code. This shows, that, as things stand at present, the Hamming code should generally continue to be used. Only if memory capacity and lower complexity have a very high priority should the MAGIC mode be used on an embedded system.


## Programm und Tests ausführen
Es gbit zwei Makefiles in diesem Projekt. Ein [Makefile](./microcontroller/cw521/makefile) ist für die Kompilierung für den Mikrocontroller zuständig. Wie man die Datei und Tests auf dem Mikrocontroller ausführt, kann man in der PDF-Datei nachlesen.

Das andere [Makefile](./microcontroller/cw521/magic_bachelorarbeit/Makefile) sorgt für eine lokale Kompilierung. Bei der lokalen Kompilierung wird eine ausführbare Datei im Ordner ``./microcontroller/cw521/magic_bachelorarbeit/bin`` erstellt, die man dann ausführen kann. Dieses Makefile erstellt erstellt außerdem in diesem Ordner mit dem Kommando ``make test`` eine ausführbare Datei für die lokale Ausführung der Tests.
