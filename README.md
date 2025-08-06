# thechatroom
Irc-style Chat Room for Reticulum Nomadnet 


descrizione contenuto:
chat_log.json = "database" json

commands.py = (incompleto) migrazione dei comandi dalla pagina principale ad uno script secondario da importare 

emoticon.txt = (incompleto) file contenente emoticon, per creazione comando /e , invia un rigo a caso del file in chat, da implementare (il primo test non funzionava :D)

fullchat.mu = pagina script per lettura full chatlog

index.mu = pagina mu python principale

intro.mu = (incompleto) test creazione intro page prima di entrare nella chat, dovrebbe mostrare intro ascii + lista di canali attivi su cui cliccare per entrarci (da implementare)

thechatroom.db = primo test db sql (non implementato nello script principale che utilizza ancora il json)

topic.json = file del topic salvato dal comando /topic

intro.mu = nuova aggiunta per la nuova versione della chat, è la landing page principale della futura versione :D

idee e work in progress:
correggere il contatore dei messaggi perchè al momento include anche il conteggio dei messaggi service dei comandi vari
implementare sql con possibilità di: creare canali chat multipli, ognuno col suo topic, i suoi messaggi e la sua lista utenti, definire diverse modalità utente (normale, op, admin)
modificare comandi in base al tipo di utente
aggiunta nuovi comandi: /e (invia random emoticon da un file di testo) /c COLOR (permette di usare il colore in chat senza usare codice micron) , /nickserv (comandi vari utili per settare il nickname, il colore del proprio nick a piacere, associare una breve descrizione al nick) /whois (richiama i dettagli associati ad un nick , /chan mostra i canali attivi dopo l'implementazione , /join #chan entra in un canale (possibile?)
idee impossibili: avvisare con messaggio service entrata e uscita degli utenti dalla chat
associare nick a identity
