# Code-Regeln

1. Eine Verantwortung pro Modul/Datei.
2. Domain bleibt frei von Framework- und OS-Abhängigkeiten.
3. Keine Secrets, Kennwörter oder API-Keys im Quellcode.
4. Kein Blocking-I/O im UI-Thread.
5. Teure Messungen cachen oder mit sinnvollen Intervallen ausführen.
6. Plattformcode hinter `cfg(target_os)` kapseln.
7. Keine erfundenen Security-Werte anzeigen.
8. Neue Security-Signale brauchen nachvollziehbare Gewichtung und Tests.
9. Keine automatische destructive Aktion ohne explizite Produktentscheidung.
10. Vor Release: format, check, test; auf beiden Zielplattformen testen.
