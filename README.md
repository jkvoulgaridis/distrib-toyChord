# distrib-toyChord@EL

Η εργασία αυτή πραγματοποιήθηκε στα πλαίσια του προπτυχιακού μαθήματος "Κατανεμημένα Συστήματα", της σχολής ΗΜΜΥ του ΕΜΠ κατά το χειμερινό εξάμηνο 2020-21. Σκοπός είναι η υλοποίηση μια απλοποίημένης έκδοση του πρωτοκόλου Chord (<https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf>) με την ονομασία toy-Chord. Συγκεκριμένα, δεν υλοποιείται η δρομολόγηση με finger tables και δεν χειριζόμαστε ταυτόρονα join/departs κόμβων με insert/delete/query δεδομένων και θεωρούμε επίσης ότι υπάρχει ένας κόμβος (bootstrap node) ο οποίος δεν αποχωρεί ποτέ και μέσω αυτού εισέρχονται νέοι κόμβοι. Η υλοποίηση του πρωτοκόλου υπάρχει στο αρχείο main_dht.py και παρακάτω ακολουθούν δύο use cases:

1) ``` python3 main_dht.py --bootstrap ```

2) ``` python3 main_dth.py --id <ip>:<port> ```

