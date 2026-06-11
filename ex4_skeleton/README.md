# Exercise 4 - Bonus: ARP Spoofing Detection

## How does our detection work?

We sniff ARP replies on the network and keep track of which IP belongs to which MAC address. If we suddenly see that an IP we already know is now claiming to have a different MAC — that's suspicious, and we flag it as a possible ARP spoof.

Once we detect something fishy, we scan the local network to try and figure out who the attacker actually is, by looking for other devices with that same MAC.

## What can we do when we detect an attack?

When we detect an attack we can eather simply alert the admin so they can investigate, send out "corrective" ARP replies with the real MAC to undo the poisoning or block the suspicious MAC at the switch level.

## Edge cases we thought about

**What if a computer legitimately changes its IP?**  
Our detector won't flag this, since we only care when the same IP suddenly points to a different MAC. But, if a new device gets an IP that was previously used by someone else, we might get a false alarm.

**Do we need to watch every single IP?**  
Attackers will probably go after important targets like a DNS server. So it makes more sense to focus our monitoring on those critical IPs rather than trying to protect everything equally, which is not practical.

## What changes fast vs. slow?

**Fast:** The attacker has to keep sending spoofed ARP replies every few seconds to keep the victim's ARP cache poisoned. So the rate of ARP replies from one source is a good indicator.
**Slow:** On a normal network, IP-to-MAC mappings barely ever change. 
## False positives vs. false negatives

**False positive** meaning we think there's an attack, but there isn't.  
This is annoying but not dangerous. The worst case is we accidentally block a legitimate user.

**False negative** meaning there's a real attack, but we miss it.  
This is the dangerous one. It means the attacker is intercepting traffic, stealing passwords, and we have no idea.
