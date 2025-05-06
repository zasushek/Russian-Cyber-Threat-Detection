# Profil zagrożeń

Wybrano cztery rosyjskie grupy hackerskie, w naszej opinii najbardziej znaczące, na których skupiono się podczas dalszej analizy i tworzenia profili zagrożeń. Są to grupy cały czas aktywne, obierające za cel różne sektory oraz dysponujące dużymi zasobami z powodu ich (prawdopodobnego) rządowego finansowania.

Wybrane grupy:

- [G0007 - APT28](https://attack.mitre.org/groups/G0007/)
- [G0016 - APT29](https://attack.mitre.org/groups/G0016/)
- [G0034 - APT44](https://attack.mitre.org/groups/G0034/)
- [G0010 - Turla](https://attack.mitre.org/groups/G0010/)

## APT28

**Aliasy:** Sofacy, Fancy Bear, STRONTIUM, Sednit

1. **Motywacja:**
   APT28 to rosyjska grupa cyberzagrożeń powiązana z wywiadem wojskowym GRU (jednostka 26165). Działa co najmniej od 2004 roku, prowadząc operacje cyberszpiegowskie wymierzone w rządy, wojsko oraz organizacje międzynarodowe (m.in. NATO).
2. **Zdolności techniczne:**
   APT28 najczęściej stosuje techniki phishingu (spearphishing e-mail z dokumentem Office lub linkiem) jako wektor początkowy. W dalszej kolejności używa narzędzi do zrzutu haseł z pamięci (dumpowanie LSASS przy pomocy Mimikatz lub własnych implantów), a także do skanowania sieci i zbierania informacji (np. używanie natywnych narzędzi systemowych – polecenia net systemu Windows, narzędzia PowerShell). W arsenale APT28 znajduje się wiele unikatowych złośliwych programów tworzonych przez grupę: m.in. rodzina trojanów CHOPSTICK/X-Agent służąca do zdalnej kontroli i kradzieży danych, moduły malware typu ADVSTORESHELL/CORESHELL (backdoory rezydujące w systemie), czy nowsze narzędzia jak Zebrocy (pakiet malware używany w atakach spearphishingowych o różnych modułach) oraz LoJax – pierwsze znane malware atakujące UEFI komputerów w celu trwałej instalacji. Grupa wykorzystuje także legalne narzędzia administracyjne w sposób niezgodny z przeznaczeniem – np. PowerShell, wbudowany certutil.exe do dekodowania i pobierania plików, czy PsExec/Scheduled Tasks do poruszania się po sieci. W przeszłości APT28 wykorzystywała też ogólnodostępne frameworki Metasploit/Koadic (np. do injekcji kodu przez DDE) oraz narzędzia do sniffingu sieci (np. Responder do przechwytywania hashy NTLM).
3. **Zarejestrowane kampanie:**
   - Hack wyborczy (USA 2016)
   - Ataki na organizacje antydopingowe (2017–2018)
   - Operacja „Nearest Neighbor” (2020)
   - Kampanie przeciwko Ukrainie i Gruzji (2014–2022)
4. **Ocena poziomu zagrożenia:**
   APT28 stanowi bezpośrednie, wysokie zagrożenie dla organizacji rządowych, wojskowych oraz sektorów związanych z polityką międzynarodową. Motywacją grupy jest cyberszpiegostwo i wpływ na procesy geopolityczne, co oznacza, że motywy ataku obejmują kradzież wrażliwych informacji i ich ewentualne wykorzystanie (np. wyciek w celu dezinformacji). Zdolności techniczne APT28 są zaawansowane – grupa wykazała się umiejętnością tworzenia własnego malware (np. rootkit LoJax, dropery, trojany) oraz stosowania 0-day exploitów. Historia ataków pokazuje ciągłą aktywność na przestrzeni kilkunastu lat i skuteczne operacje przeciw wysoko zabezpieczonym celom (DNC, MS Office 365 w kampaniach phishingowych).

## APT29

**Aliasy:** Cozy Bear, The Dukes, NOBELIUM

1. **Motywacja:**
   APT29 to elitarna grupa APT powiązana z rosyjską Służbą Wywiadu Zagranicznego (SVR). Działa co najmniej od 2008 roku i znana jest z wyrafinowanych kampanii cyberszpiegowskich przeciw instytucjom rządowym (zwłaszcza ministerstwom spraw zagranicznych), organizacjom międzynarodowym i sektorowi badawczo-naukowemu w krajach NATO.
2. **Zdolności techniczne:**
   APT29 stosuje bardzo podobny zestaw technik jak APT28, kładąc jednak większy nacisk na ataki na usługi chmurowe oraz zaawansowane unikanie wykrycia. Typowe jest spearphishing (często z linkami) jako wektor początkowy, po którym grupa intensywnie używa PowerShell do zadań poeksploatacyjnych. APT29 słynie z rozwiniętej rodziny własnego malware określanej jako Duke – m.in. MiniDuke, CozyDuke, CloudDuke, CosmicDuke, FatDuke – wykorzystywanego w różnych fazach ataku. W ataku SolarWinds wprowadzili backdoory SUNBURST, TEARDROP, Raindrop do sieci ofiar. W arsenale mają także FoggyWeb (backdoor do serwerów AD FS) oraz korzystają z narzędzi open-source: np. Cobalt Strike (komercyjny framework Red Team) został użyty w późniejszych etapach SolarWinds. Co istotne, APT29 sięga po Mimikatz do dumpowania haseł, AdFind i BloodHound do enumeracji, oraz tworzy własne narzędzia do manipulacji środowiskiem Azure/Office 365 (np. skrypty AADInternals). Grupa znana jest z czyszczenia śladów – po osiągnięciu celu usuwa narzędzia i wyłącza logowanie (np. Auditpol), aby utrudnić detekcję.
3. **Zarejestrowane kampanie:**
   - Operacja SolarWinds (2020)
   - Ataki na sektor ochrony zdrowia (2020)
   - Operacja Ghost (2019)
   - Włamania do think-tanków i MSZ (2016–2021)
4. **Ocena poziomu zagrożenia:**
   APT29 to zagrożenie bezpośrednie (wysoki priorytet) dla instytucji rządowych, dyplomatycznych, sektora obronnego oraz firm posiadających cenne informacje strategiczne (np. w energetyce, farmacji). Grupa ma wysokie zdolności techniczne – demonstrowała umiejętność przełamywania nawet zaawansowanych zabezpieczeń (atak na łańcuch dostaw, zaawansowane backdoory) i działania w ukryciu przez długi czas. Motywy ataku to cyberszpiegostwo państwowe – APT29 wybiera cele o wysokiej wartości wywiadowczej, nie atakuje losowych firm dla okupu.

## APT44

**Aliasy:** Sandworm Team, Quedagh, BlackEnergy, Voodoo Bear, Telebots

1. **Motywacja:**
   APT44 (znana szerzej jako Sandworm Team) to wyjątkowo destrukcyjna rosyjska grupa APT, powiązana z wywiadem wojskowym GRU. Działa co najmniej od 2009 roku i zasłynęła z cyberataków sabotażowych wymierzonych głównie w Ukrainę oraz instytucje zachodnie.
2. **Zdolności techniczne:**
   APT44 wyróżnia się użyciem złośliwego oprogramowania typu wiper i narzędzi dedykowanych ICS. Najbardziej znane narzędzia grupy to: BlackEnergy, Industroyer/CrashOverride, czy NotPetya. Ponadto APT44 korzysta z innych narzędzi, np. Mimikatz do kradzieży haseł (użyty w NotPetya), własne skrypty PS do rozprzestrzeniania malware (TankTrap), implanty backdoor (np. Exaramel powstały z Industroyera), czy framework Metasploit (wykorzystany do injekcji DLL przy podnoszeniu uprawnień). Grupa często stosuje techniki używania natywnych narzędzi systemowych, takie jak PsExec do rozsyłania KillDisk (2015), a w 2016 w trakcie ataku na energetykę posłużono się wbudowanymi narzędziami Windows (schtasks, net use) do poruszania się w sieci.
3. **Zarejestrowane kampanie:**
   - BlackEnergy (Ukraina 2015)
   - CrashOverride (Ukraina 2016)
   - NotPetya (czerwiec 2017)
   - Olympic Destroyer (2018)
4. **Ocena poziomu zagrożenia:**
   APT44/Sandworm to bez wątpienia jedno z najbardziej niebezpiecznych zagrożeń (wysoki priorytet), zwłaszcza dla sektorów infrastruktury krytycznej (energetyka, transport, łączność) oraz w kontekście konfliktu z Rosją. Motywy ataku tej grupy wykraczają poza szpiegostwo – obejmują bezpośrednie niszczenie systemów i zakłócanie usług na dużą skalę dla efektu sabotażu militarnego lub politycznego. Zdolności techniczne Sandworm są bardzo zaawansowane w niszowych obszarach (ICS, IoT) – żadna inna grupa nie ma takiego doświadczenia w atakach na sieci energetyczne.

## Turla

**Aliasy:** Venomous Bear, Snake, IRON HUNTER

1. **Motywacja:**
   Turla to długo działająca rosyjska grupa APT powiązana z Federalną Służbą Bezpieczeństwa (FSB). Działa od co najmniej 2004 roku, a jej kampanie dotknęły ponad 50 krajów. Turla specjalizuje się w cyberszpiegostwie ukierunkowanym – za cel obiera zwykle placówki rządowe, dyplomatyczne (ambasady, MSZ), organizacje badawcze i wojskowe.
2. **Zdolności techniczne:**
   Turla jest znana z szeregu unikatowych narzędzi malware, rozwijanych samodzielnie i używanych wyłącznie przez tę grupę, m.in.: Snake (Uroburos), ComRAT (wariant Agent.BTZ), Carbon (Cobra). Poza własnym arsenałem, Turla korzysta też z innych narzędzi: wykorzystywała np. Meterpreter (Metasploit) do injekcji DLL, sięgała po Mimikatz i Responder (narzędzie do sniffingu sieci). Ciekawą praktyką Turli jest „piggybacking” – przejmowanie infrastruktury innych APT. Przykładowo, w 2018 zidentyfikowano, że Turla przejęła serwery C2 należące wcześniej do irańskiej grupy OilRig (APT34) i używała ich malware (po lekkiej modyfikacji). Najczęstsze techniki Turli skupiają się na ukryciu: malware grupy często działa w pamięci (fileless), komunikacja jest tunelowana przez legalne usługi (OneDrive, Gmail), a komponenty są modularne, co utrudnia analizę (każdy moduł wykonuje osobne zadanie – kradzież plików, przechwytywanie klawiatury, itp.). Turla wyróżnia się także długością swoich operacji – potrafi utrzymywać infekcje latami, aktualizując narzędzia, by pozostać niewykryta.
3. **Zarejestrowane kampanie:**
   - Epic Turla (2014)
   - Ataki na satelity (2007–2015)
   - WhiteBear (2016–2017)
   - Poisoned Watering Holes (2019)
   - Crutch (2020)
4. **Ocena poziomu zagrożenia:**
   Turla stanowi zagrożenie bezpośrednie (wysokie) głównie dla sektorów rządowego, dyplomatycznego, wojskowego – czyli dla organizacji posiadających informacje istotne z punktu widzenia bezpieczeństwa Rosji. Motywy ataku Turli są czysto wywiadowcze – zdobycie poufnych danych, bez działań destrukcyjnych. Zdolności techniczne są bardzo wysokie, zwłaszcza w zakresie unikania wykrycia i customizacji malware. Turla dysponuje unikatowymi narzędziami i potrafi prowadzić operacje stealth latami, co czyni ją trudnym przeciwnikiem do wykrycia.
