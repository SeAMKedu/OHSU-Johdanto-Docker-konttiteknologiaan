# Konttiteknologioiden hyödyntäminen ohjelmistojen kehitys-, ja ajoympäristöissä

## Johdanto

**Docker** on laajasti käytetty työkalu joka helpottaa sovelluskehitysympäristöjen hallintaa, sekä sovellusten paketointia, ja näiden pakettien käsittelyä ja asentamista erilaisiin ajoympäristöihin. Dockerin avulla sovelluksia ja ohjelmistokehitysympäristöjä voidaan käsitellä vakioituina komponentteina, eli kontteina (container). Docker soveltuu sekä  ohjelmointiin tutustuvalle aloittelijalle että alan ammattilaisille.

Dockeria hyödynnetään pääasiassa Linux-pohjaisten palvelinsovellusten yhteydessä. Arviolta yli 95 % maailman palvelinkoneista hyödyntää Linux-käyttöjärjestelmää, esimerkiksi Java-, PHP-, JavaScript- tai Python-ohjelmointikielillä toteutettujen ohjelmistojen ajoon. Dockerin mahdollinen sovellusalue on siis laaja. 

Konttien käyttö on hyvin yleistä sekä yksinyrittäjien tuotanto- ja kehitysympäristöissä, että jättiyritysten miljoonien käyttäjien ympäristöissä. Useimmat pilvialustat kuten Microsoft Azure, Amazon Web Services, Google Cloud ja monet muut, tukevat kontti-sovelluksia. Sovellusten asennus ja hallinnointi pilvialustoilla on helpompaa silloin kun käytetään kontteja.

Tässä oppaassa esitellään Dockerin rooli yhtenä tietotekniikan työkaluna. Opas esittelee Dockerin tyypillisiä käyttötapauksia, kuten paikallisen ohjelmistokehitysympäristön pystytys, ja ohjelmistojen tuotantoon vientiin ja ohjelmistotestaukseen liittyviä esimerkkejä. Opas on suunnattu aloitteleville ohjelmistokehittäjille, järjestelmäasiantuntijoille ja muille konttiteknologioista kiinnostuneille. Esitiedoiksi riittää perustason ymmärrys tietokoneiden ja tietoverkkojen toimintaperiaatteista.

Docker on [konttijärjestelmistä](https://fi.wikipedia.org/wiki/S%C3%A4ili%C3%B6inti) tunnetuin. Vastaavia (kuten Podman) tai laajempia (kuten Kubernetes), pitkälle yhteensopivia, ratkaisuja löytyy useita. Esimerkiksi Googlen kehittämä Kubernetes keskittyy konttien hallintaan useiden palvelinkoneiden muodostamassa kokonaisuudessa (container orchestration in server cluster). Tämä opas keskittyy vain konttiteknologioiden perusteisiin Docker:ia hyödyntäen. Konttiteknologioiden periaatteet ovat yleispäteviä, joten Dockerin toimintaperiaatteiden ymmärtämisestä on hyötyä myös muiden konttiteknologiaa hyödyntävien teknologioiden, kuten Kubernetes, käytössä.

### Docker Desktop

Dockerin komentorivipohjaiset perustyökalut on julkaistu avoimen lähdekoodin lisenssillä ja niitä voi käyttää vapaasti ja veloituksetta. **Docker Desktop** on erillinen Docker Inc. -yrityksen kaupallinen tuote. 

**Docker Desktop on graafinen työpöytäohjelma** joka helpottaa Dockerin käyttöä Microsoftin Windows-, ja Applen MacOS-työpöytäympäristöissä. **Dockerin käyttö on usein helpointa aloittaa Docker Desktop -sovelluksen avulla** ja se on yleisesti myös ohjelmistokehityksen ammattilaisten käytössä.

*Mikäli aiot hyödyntää Docker Desktopia yritystoiminnassa, perehdy tuotteen käyttöehtoihin. Docker Desktop on maksullinen sovellus, mikäli yrityksen liikevaihto ylittää tietyn rajan.*

Vaihtoehtoisesti, Docker:ia voi käyttää Windows- ja Mac-ympäristöissä myös asentamalla Docker:in virtuaalikoneessa (VirtualBox, VMWare, Parallels, tms.) ajettavaan Linuxiin. Tällöin ei tarvita Docker Desktop -ohjelmistoa, mutta käytössä ei myöskään ole graafista käyttöliittymää konttien hallintaan. Docker-virtuaalikoneen asennuksen voi myös automatisoida (kts. [Vagrant](https://developer.hashicorp.com/vagrant/docs/provisioning/docker)). 

Myös Docker Desktop vaatii toimiakseen Linux-virtuaalikoneen jossa Docker-kontteja ajetaan, mutta Docker Desktop hoitaa kaiken automaattisesti. **Docker Dektopin suurin etu on helppous, sen avulla Docker-ympäristön käyttöönotto onnistuu muutamalla klikkauksella.**

Docker Desktopin tarjoama graafinen käyttöliittymä konttien hallintaan ei ole välttämätön, ja Dockerin operointi [komentorivin](https://fi.wikipedia.org/wiki/Komentoliittym%C3%A4) kautta onkin tyypillisin tapa käyttää Dockeria. Docker Desktopin tarjoama graafinen käyttöliittymä on helppo tapa käynnistää Docker-ympäristö, ja joidenkin asioiden tekeminen voi olla helpompaa graafisen käyttöliittymän kautta. Komentorivin tuntemus on kuitenkin lähes välttämätöntä Dockerin käytössä. Tämä opas pyrkii tarjoamaan tarvittavat perustiedot myös komentorivin käyttöön.


### Virtualisointi

[Virtualisointi](https://fi.wikipedia.org/wiki/Virtualisointi) tarkoittaa tietotekniikassa menetelmiä, joissa esimerkiksi tietokoneen fyysiset resurssit (**rautatason virtualisointi**), tai käyttöjärjestelmän ydin (**käyttöjärjestelmätason virtualisointi**), piilotetaan muilta järjestelmiltä jotka käyttävät näitä resursseja.

Rautatason virtualisointi (**Hardware virtualization**) mahdollistaa usean käyttöjärjestelmän ajamisen yhtäaikaisesti samalla raudalla, esimerkiksi yksittäisellä palvelintietokoneella. Rautatason virtualisointi voi esimerkiksi helpottaa vanhojen ([legacy](https://en.wikipedia.org/wiki/Legacy_system)) Windows Server-sovellusten ylläpitoa konesaliympäristössä. Virtuaalikoneiden hyödyntäminen konesaleissa on hyvin yleistä.

Rautatason virtualisointi on laajasti hyödynnetty teknologia jolla on monia erilaisia sovelluksia. Tämä opas keskittyy kuitenkin käyttöjärjestelmätason virtualisointiin (**OS-level virtualization**) **konttiteknologioiden** avulla. 

Käyttöjärjestelmätason virtualisoinnin yleisin sovellus lienee Linux-pohjaisten ohjelmistojen ajaminen konteissa, esimerkiksi Dockerin avulla. Sovellusten "kontittaminen" tarjoaa monia samankaltaisia sovelluskonfiguraation ja ympäristön vakiointiin liittyviä etuja, kuin rautatason virtualisointi. Konttien käyttö on kuitenkin rautavirtualisointia huomattavasti tehokkaampi ja "kevyempi" ratkaisu.

#### Kontti

Kuten edellä mainittiin, **käyttöjärjestelmätason virtualisointi tarkoittaa käytännössä konttiteknologioiden hyödyntämistä**. Termi kontti viittaa merikontteihin. Merikonttien käyttöönoton myötä laivojen lastaus sekä purku, ja globaali logistiikka ylipäätään, on tehostunut merkittävästi. Rahtilaivan lastaajan ei tarvitse tietää kovinkaan tarkasti mitä jokainen merikontti sisältää. Kuitenkin jokainen kontti pystytään käsittelemään samoilla menetelmillä ilman pelkoa siitä että yhden kontin sisältö vaikuttaa muihin kontteihin tai rahtilaivaan.

**Ohjelmistokontit tehostavat ohjelmistojen käsittelyä  kuten merikontit tehostavat logistiikkaa.** Riippumatta kontin sisällöstä, sen sisältämää ohjelmistoa pystytään ajamaan helposti millä tahansa konttiteknologiaa tukevalla tietokoneella. Esimerkiksi kehitysvaiheessa konttia voidaan ajaa kannettavalla tietokoneella, testausvaiheessa oman konesalin palvelimella ja tuotannossa pilvipalvelutarjoajien, kuten Amazon Web Services tai Microsoft Azure, ympäristöissä. Vakioidun konttiympäristön ansiosta, käyttöönotossa ei kontin lisäksi tarvitse asentaa mitään muuta, koska kaikki tarvittava on valmiiksi mukana kontissa. Konttiteknologian avulla uuden internetpalvelun julkaiseminen pilvipalvelualustalle Internetiin, voi onnistua minuuteissa ohjelmiston valmistumisesta.

 Virtuaalikoneiden käsittely konesaliympäristössä on selkeää. Tällöinkin käsitellään vakiokomponentteja, joiden sisällöllä on vähän merkitystä käsittelijälle. Esimerkiksi kokonaisten virtuaalikoneiden varmuuskopiointi on konesaliympäristöissä yleistä. Virtuaalikoneetkin siis tarjoavat samankaltaisia etuja kuin merikontit. Ohjelmistokontit, toisin kuin virtuaalikoneet, eivät kuitenkaan sisällä erillistä käyttöjärjestelmää. Tämän vuoksi kontit voivat olla hyvin pieniä, esimerkiksi vain muutaman megatavun kokoisia, ja ne käynnistyvät hyvin nopeasti, koska isäntä-Linux (**host**) on jo valmiiksi käynnissä konttia käynnistettäessä. **Docker-kontit voikin mieltää tavaksi paketoida Linux-sovelluksia helposti hallittaviksi itsenäisiksi kokonaisuuksiksi joita voidaan ajaa turvallisesti dockerin tarjoamassa hiekkalaatikossa ([sandbox](https://en.wikipedia.org/wiki/Sandbox_(computer_security)))**.

 ### Terminologiaa

 Edellä puhuttiin yksinkertaisuuden vuoksi tarkoituksella virheellisesti pelkästään konteista.
 **Täsmällisempää on puhua erikseen kontista ja imagesta.**
 Konteilla tarkoitetaan ajossa olevaa kontti-imagea.
 Silloin kun "kontti" on vain arkistoituna tai ajoa odottamassa levyllä, oikea termi on image. 
 
 **Docker-kontti on siis oikeasti kontti vain silloin kun se on ajossa konttijärjestelmässä, muulloin tulisi käyttää termiä Docker-image.** Puhekielessä tätä eroa ei aina tehdä, ja voidaan puhua yleisesti konteista, mutta esimerkiksi Dockerin manuaaleissa tehdään selkeä ero näiden kahden käsitteen välille. 
 
 Sekä merikontteja että Docker:ia voi käyttää varastointiin. Docker-kontin voi "varastoida" levylle Docker-imagena, ja merikontin voi hankkia vaikka omalle takapihalle varastoksi. Kuitenkin **merikontti toteuttaa tarkoitustaan silloin kun se liikkuu lastattuna, ja Docker-kontti silloin kun sen sisältämä sovellus on käynnissä.**
  
 Suomenkielinen terminologia aiheesta ei ole kovin vakiintunutta, joten alla on listattu joitain suomenkielisiä vastineita *image*- ja *container*-termeille.
 
 - **Docker Image**: Docker-kuva, kontti-image, näköistiedosto ("ohjelmisto on varastossa")
 - **Docker Container**: kontti, säiliö ("ohjelmisto on ajossa")

 *Docker Inc. ja Microsoft markkinoivat myös "Windows-kontteja". Nämä ovat Windows Server virtuaalikoneita joita voi hallinnoida tavanomaisilla Docker komennoilla Windows Server -ympäristössä. Toiminnallisuuden tekninen toteutus poikkeaa merkittävästi perinteisistä Docker-konteista. Windows-konttien käyttö lienee harvinaista, eikä tämä opas käsittele asiaa tämän enempää.*

### Sovelluskehitysympäristöt

Aiemmin johdannossa keskityttiin sovellusten ajoympäristöihin, mutta myös sovelluskehitysympäristöt mainittiin. Dockerin käyttö soveltuvien ohjelmistokehitysympäristöjen vakioinnissa tarjoaa useita etuja. Ohjelmoinnin aloittaminen voi olla Docker:in kanssa jopa helpompaa, koska koodieditoria lukuun ottamatta, muut ohjelmointityökalut voi asentaa Dockerin avulla.

Docker mahdollistaa yhtenäisen ja toistettavan kehitysympäristön luomisen, mikä vähentää ohjelmistokehityksessä yleisiä “toimii minun koneellani” -ongelmia. Docker-konttien avulla on helppo varmistaa, että kehitystiimin jokainen jäsen työskentelee sovelluksen kannalta identtisessä ympäristössä. 

 Dockerin avulla voi myös helposti luoda erilliset kontit eri projekteille. Jokainen kontti voi sisältää esimerkiksi eri Python version. Näin erilaisilla työkaluilla toteutettuja projekteja voi kehittää samalla työasemalla ilman ympäristökonflikteja.

#### Ohjelmistoversiot

Nykyaikaiset ohjelmistot hyödyntävät laajasti erilaisia valmiita ohjelmistokirjastoja. Ohjelmistokirjastot ovat kokoelmia valmiiksi koodattuja toimintoja, joita ohjelmoijat voivat hyödyntää omassa koodissaan välttääkseen samojen toimintojen uudelleenkirjoittamisen. 

Tässä on yksinkertainen esimerkki pseudokoodina:
```python
# Matematiikkakirjaston tuonti (import)
import matematiikkakirjasto
# Kahden luvun summan laskeminen käyttäen kirjaston funktiota
summa = matematiikkakirjasto.laskeSumma(5, 3)
# Tulostetaan summa
print("Lukujen summa on:", summa)
```

Ylläolevassa esimerkissä matematiikkakirjasto voisi olla joku toisen osapuolen toteuttama kirjasto, jonka uusin versio otetaan kehitysvaiheessa käyttöön omaan sovellukseen. Tällöin toteutetussa ohjelmassa on riippuvuus juuri tähän tietyn ajanhetken versioon kyseisestä kirjastosta. 

Ajan saatossa kirjastoista julkaistaan uusia versioita, jotka eivät välttämättä enää toimi samalla tavalla. Kirjaston tahaton päivittäminen, tai muusta syystä johtuva väärän version käyttäminen, saattaisi rikkoa sovelluksen.

Laatimamme ohjelmisto on toteutettu tietyn ohjelmointikielen tietyllä versiolla, esimerkiksi Python 3.12.3. Emme voi olettaa että sovellus toimisi millä tahansa versiolla, vaan yleensä halutaan lukita sovelluksen ajoympäristöksi tietty ohjelmointikielen versio. 

Ohjelmamme saattaa hyödyntää myös joitan ulkopuolisia komentoja. Haluamme mahdollisesti hakea verkosta jotain tietoja Linuxin [curl](https://en.wikipedia.org/wiki/CURL)-komennolla sovelluksessamme. Tällöin on tarpeen varmistaa myös että ajoympäristöstä riippumatta sovellus hyödyntää tätä tiettyä versiota curl-työkalusta.

Ohjelmistokirjastojen versioiden hallintaan löytyy toki Dockerin lisäksi muitakin ratkaisuja, ja näitä hyödynnetään yleisesti myös konttien yhteydessä. Samoin ulkopuolisten työkalujen ja ohjelmointikielten versioiden hallinta onnistuu Linuxin paketinhallinnan versioinnin avulla. Docker kuitenkin selkeyttää myös näitä, ja mahdollistaa erilaisten versioiden määrittelyn hallitusti ja selkeästi yhdessä paikassa, Dockerin [Dockerfile](https://docs.docker.com/reference/dockerfile/)-konfiguraatiotiedostossa. Tyypillistä on lopulta antaa versionumerot myös valmiille Docker-imageille jolloin tämän yhden versionumeron avulla voidaan tarvittaessa selvittää sovelluksen kaikkien riippuvuuksien versiot.

## Jatko-opiskelu

Nyt lukija tuntee taustan ja tarpeeksi teoriaa, jotta voi jatkaa opiskelua netistä löytyvien materiaalien avulla. Seuraavassa on listattu englannin kielisiä linkkejä olennaisimpiin tutoriaaleihin:

- [Dockerin virallinen dokumentaatio](https://docs.docker.com/get-started/)
- [Docker Hub](https://hub.docker.com/)
- [Dockerfile-referenssi](https://docs.docker.com/engine/reference/builder/)
- [Docker Compose -opas](https://docs.docker.com/compose/gettingstarted/)
- [Docker Compose -referenssi](https://docs.docker.com/compose/compose-file/)
- [Kubernetesin virallinen dokumentaatio](https://kubernetes.io/docs/home/)
- [Kubernetesin aloittelijan opas](https://kubernetes.io/docs/tutorials/kubernetes-basics/)

CSC – Tieteen tietotekniikan keskus ylläpitää konesalipalveluita joita oppilaitokset ja opiskelijat voivat hyödyntää jopa maksutta. CSC:llä on tarjolla konttiaiheista johdantomateriaalia jota pystyy halutessaan koettamaan oikeassa konttien orkestraation tarkoitetussa kubernetes-yhteensopivassa ympäristössä.

- [CSC:n johdanto kontteihin](https://docs.csc.fi/cloud/rahti2/containers/)
- [Lecture notes on the Rahti 2 Kubernetes sevice](https://rahti-course.a3s.fi/)
- [Johdanto CSC:n Kubernetes-yhteensopivan Rahti-palvelun käyttöön](https://docs.csc.fi/cloud/rahti/rahti-what-is/)


### Docker Compose

Docker Compose on työkalu, joka mahdollistaa monisäiliöisten Docker-sovellusten määrittelyn ja ajamisen. Compose käyttää YAML-tiedostoa sovelluksen palveluiden määrittelyyn. Tämän avulla voit määritellä ja hallita kaikkia sovelluksesi palveluita yhdessä paikassa.

Hyödyllisiä resursseja Docker Composen oppimiseen:
- [Docker Compose -opas](https://docs.docker.com/compose/gettingstarted/)
- [Compose-referenssi](https://docs.docker.com/compose/compose-file/)

### Kubernetes

Kubernetes on avoimen lähdekoodin järjestelmä, joka automatisoi konttien käyttöönoton, skaalaamisen ja hallinnan. Se tarjoaa alustan, jolla voit hallita konttien orkestrointia ja varmistaa, että sovelluksesi toimivat luotettavasti ja tehokkaasti.

Hyödyllisiä resursseja Kubernetesin oppimiseen:
- [Kubernetesin virallinen dokumentaatio](https://kubernetes.io/docs/home/)
- [Kubernetesin aloittelijan opas](https://kubernetes.io/docs/tutorials/kubernetes-basics/)
- [Kubernetes Academy](https://kubernetes.academy/)

Näiden resurssien avulla voit syventää osaamistasi ja oppia lisää Dockerin, Docker Composen ja Kubernetesin käytöstä. Onnea matkaan konttiteknologioiden parissa!

## Lopuksi

Tämä johdanto tutustutti lukijan konttiteknologiaan. Dockerin avulla voit hallita sovelluksesi riippuvuuksia ja varmistaa, että se toimii johdonmukaisesti eri ympäristöissä. Docker Compose ja Kubernetes tarjoavat tehokkaita työkaluja monimutkaisempien sovellusten hallintaan ja orkestrointiin. Jatka oppimista ja kokeile erilaisia skenaarioita, jotta voit hyödyntää näitä teknologioita parhaalla mahdollisella tavalla omissa projekteissasi.