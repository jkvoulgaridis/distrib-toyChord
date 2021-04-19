# distrib-toyChord@EL

Η εργασία αυτή πραγματοποιήθηκε στα πλαίσια του προπτυχιακού μαθήματος "Κατανεμημένα Συστήματα", της σχολής ΗΜΜΥ του ΕΜΠ κατά το χειμερινό εξάμηνο 2020-21. Σκοπός είναι η υλοποίηση μια απλοποίημένης έκδοση του πρωτοκόλου Chord (<https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf>) με την ονομασία toy-Chord. Συγκεκριμένα, δεν υλοποιείται η δρομολόγηση με finger tables και δεν χειριζόμαστε Ηταυτόρονα join/departs κόμβων με insert/delete/query δεδομένων και θεωρούμε επίσης ότι υπάρχει ένας κόμβος (bootstrap node) ο οποίος δεν αποχωρεί ποτέ και μέσω αυτού εισέρχονται νέοι κόμβοι. Η υλοποίηση του πρωτοκόλου υπάρχει στο αρχείο main_dht.py και παρακάτω ακολουθούν δύο use cases:

1) ``` python3 main_dht.py --bootstrap --replication_factor <k> --policy <EC|L> ```

Η παραπάνω εντολή χρησιμοποιείται για την εκκίνηση του bootstrap node. Ο bootstrap ρυθμίζει το replication factor και την πολιτική συνέπειας για όλο το δίκτυο. Τα ορίσματα ```replication_factor``` και ```policy``` είναι προαιρετικά. Επίσης, η ip και το port του Bootstrap είναι hard coded στο αρχείο main_dht.py

2) ``` python3 main_dth.py --id <ip>:<port> ```

Η παραπάνω εντολή χρησιμοποιείται για την είσοδο ενός κόμβου στο δίκτυο (εκτός του bootstrap). 

Επίσης, για την διαχείριση και την αλληλεπίδραση με το πρωτόκολο υπάρχει και ένα CLI στο αρχείο cli.py. Η σύνταξη για το cli είναι η ακόλουθη:

 ``` python3 cli.py --id <ip>:<port> --command <cmd> {args} ```

όπου το  --id είναι η διεύθυνση του κόμβου στον οποίο απευθύνεται το αίτημα command. 

## Εγκατάσταση 

``` git clone <url_to_proj> ``` 

Προς το παρόν, δεν υπάρχει αρχείο requirements.txt οπότε τυχόν dependencies πρέπει να εγκατασταθούν χειροκίνητα.

# distrib-toyChord@EN

This project is part of the undergrad. Course Distributed Systems @ECE NTUA, Gr. A simplified version of Chord protocol (<https://pdos.csail.mit.edu/papers/ton:chord/paper-ton.pdf>) is implemented. In particular, this implementation does not support finger tables routing, simultaneous join/departs or simultaneous [joins, departs] / [inserts,deletes,queries]. In addition, we also consider that there is 1 node (bootstrap node) that never departs from the DHT. The protocol's implementaion is main_dht.py file and 2 use cases are demostrated below: 

1) ``` python3 main_dht.py --bootstrap --replication_factor <k> --policy <EC|L> ```

This use cases shows how to boot the bootstrap node, whose ip and port are hard coded in main_dht.py. The optional args --policy and --replication_factor are use to set these parameters (consistency policy and replication factor) for the whole dht. We implement two consistency policies (linearisability through Chain Replication and Eventual Consistency).   

2) ``` python3 main_dth.py --id <ip>:<port> ```

This command is used to launch a new node and join to the dht. 


## Instalation 

``` git clone <url_to_proj> ``` 

For now, there is no requirements.txt so all package dependancies should be installed manually. 
