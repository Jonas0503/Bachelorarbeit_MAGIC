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
