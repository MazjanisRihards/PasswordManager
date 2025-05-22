# PasswordManager

## Projekta uzdevums

Projekta uzdevums ir izveidot programmu, kas ļauj droši saglabāt un piekļut savām parolēm. Saglabātās paroles tiek pasargātas ar hash funkcijām un pie tām piekļūt var tikai zinot programmas galveno paroli.  
  
Eksistē vairākas paroļu menedžeru aplikācijas kā 'Lastpass' un 'Bitwarden', bet tajās paroles tiek glabātas serveros, kas pieder kompānijai kas aplikāciju izplata. Ja tādai kompānija rodas datu noplūde tad saglabātās paroles var tikt kompromizētas. Šīs aplikācijas var uz brīžiem arī nestrādāt servisa 'maintenance' laikā. Šī projekta aplikācijas priekšrocība ir tajā, ka paroles tiek saglabātas lokāli.


## Lietotās bibliotēkas

1. tkinter - Izmanto programmas grafiskā interfeisa veidošanai
2. json - Izmanto lai string objektu pārveidotu json formātā un atpakaļ, lai vieglāk saglabatu, lasītu un apstrādātu datus
3. os - Izmanto vieglākai failu veidošanai un rediģēšanai
4. base64 - Izmanto string objektu pārveidošanai bināros datos un atpakaļ
5. cryptography - Izmanto paroļu pasargāšanai šifrējot datus
6. pyperclip - Izmanto lai paroli kopētu
7. hashlib - Izmanto lai lietotu hash algoritmus

## Lietotās datu struktūras

1. Dictionaries - Katrs paroles ieraksts tiek glabāts kā vārdnīca ar atslēgām.
2. Lists - Tiek izmantots paroļu lejupielādei.
3. Tuples - Tiek izmantoti elementu grupēšanai

## Programmatūras izmantošanas metodes

1. Pierakstīties - Izmantojot programmas paroli tiek gūta piekļuve pie saglabāto paroļu saraksta
2. Saglabāt paroli - Tiek doti 3 ievades lauki (Mājaslapa; Lietotājvārds, parole). Aizpildot visus laukus un nospiežot pogu saglabāt paroli, dati no ievades laukiem tiek saglabāti teksta failā, kur lietotājvārds un parole ir pasargāti izmantojot hash funkcijas
3. Skatīt visas saglabātās paroles - Visas saglabātās paroles kopā ar saistītajām mājaslapām un lietotājvārdiem tiek parādītas sarakstā
4. Rediģēt paroli - Izvēlētā parole, lietotājvārds vai mājaslapa tiek rediģēta
5. Izdzēst paroli - Izvēlētā parole tiek dzēsta
6. Kopēt paroli - Izvēlētā parole tiek kopēta uz 'clipboard'
7. Lejupielādēt paroles - Tiek izveidots fails kurā tiek ierakstītas izvēlētās paroles uz kurām nav izmantotas hash funkcijas

## Dati programmas sagatavošanai

### Programmas parole

Parole: "1"

### Komanda nepieciešamo bibliotēku instalācijai

pip install -r requirements.txt