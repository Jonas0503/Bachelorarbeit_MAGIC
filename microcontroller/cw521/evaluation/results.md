# Interpretation der Evaluierungsergebnisse

## MAGIC

- Ver- und Entschlüsselung: steigen linear an
- Hash key finden:
    - Changing blocks: steigt linear an
    - Changing threshold: keine Aussage möglich -> wahrscheinlich exponentiell (sehr lange)
- Tag/Token Generierung: steigt linear an
- Verify:
    - Changing blocks: steigen alle (schwach) linear an und bis auf "no_error" dauert alles ca. gleich lang
    - Changing faulty block: Es spiel keine Rolle, in welchem Block der Fehler ist (auch wenn 2 Blöcke betroffen sind)
    - Changing threshold: alles dauert ca. gleich lang und der threshold spielt keine Rolle (dauert immer gleich lang)


## Hamming-Code pro Block

- add parity: Nur ein Block geht viel schneller als der Rest? Ansonsten steigt alles linear an. Nur ab 150 Blöcken funktioniert die Zeitmessung nicht mehr richtig. Vielleicht zu viel Speicher genutzt?
- verify:
    - changing blocks: Steigt linear an, nimmt aber tendenziell leicht ab, je größer die Blockanzahl wird (bei no_error). Ansonsten steigt es linear an. Verglichen zwischen der Fehleranzahl dauert alles gleich lang (nur bei zwei Fehlern dauert es kürzer, da vorher aus der Schleife gegangen wird -> könnte man auch anders machen, sodass auch dies gleich lang läuft)
    - changing faulty block: Bei einem Fehler ist es egal, in welchem Block der Fehler ist. Bei zwei Fehlern nicht (siehe oberer Punkt)
    - changing number of affected blocks: Spielt keine Rolle, wie viele Blöcke betroffen sind. Bei zwei Fehlern dauert es kürzer aus schon genannten gründen


## Hamming-Code über alle Blöcke

- add parity: Alles steigt linear an. Nur ab 150 Blöcken funktioniert die Zeitmessung nicht mehr richtig. Vielleicht zu viel Speicher genutzt?
- verify:
    - changing blocks: Steigt alles linear an. Nur bei one_bit_error dauert es im Gesamten länger, da der Block noch korrigiert werden muss
    - changing faulty block: Die Anzahl der Blöcke macht keinen Unterschied


## Vergleich von verify

Hamming-Code braucht viel weniger Zeit, um Blöcke zu verifizieren, wobei die Korrektur dort über alle Blöcke hinweg schneller ist


## Complete

MAGIC braucht in allen Fällen viel länger. Hamming-Code ist über alle Blöcke hinweg schneller
