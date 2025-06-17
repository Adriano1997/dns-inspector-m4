#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <net/netns/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - DNS Packet Inspector Advanced");

static unsigned int m4_net_id;
static unsigned long dns_packet_count = 0;

// Lista statica dei domini da bloccare
static const char *blacklist[] = {
    "bad.com",
    "malicious.net",
    "evil.org",
    NULL
};

struct m4_netns_data {
    struct nf_hook_ops nf_hops;
};

// Estrae il domain name dal payload DNS
static char *extract_domain_name(const unsigned char *data, char *buffer, size_t len) {
    int i = 0, j = 0, label_len;

    if (!data || !buffer) return NULL;

    while (data[i] != 0 && j < len - 1) {
        label_len = data[i++];
        if (label_len + i >= len) break;

        for (int k = 0; k < label_len && j < len - 2; k++) {
            buffer[j++] = data[i++];
        }
        buffer[j++] = '.';
    }

    if (j > 0) buffer[j - 1] = '\0';
    else buffer[0] = '\0';

    return buffer;
}

// Controlla se un domain è in blacklist
static int domain_in_blacklist(const char *domain) {
    char domain_lc[256];
    int i;

    for (i = 0; domain[i] && i < sizeof(domain_lc) - 1; i++) {
        domain_lc[i] = tolower(domain[i]);
    }
    domain_lc[i] = '\0';

    for (i = 0; blacklist[i]; i++) {
        if (strncasecmp(domain_lc, blacklist[i], strlen(blacklist[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

// Funzione principale del Netfilter hook
static unsigned int m4_nf_callback(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *data;
    char domain[256];

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr))) return NF_ACCEPT;

    udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (!udph) return NF_ACCEPT;

    if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) {
        dns_packet_count++;
        data = (unsigned char *)udph + sizeof(struct udphdr) + 12;
        extract_domain_name(data, domain, sizeof(domain));

        printk(KERN_INFO "[M4-Advanced] DNS packet #%lu from %pI4 to %pI4, domain: %s\n",
               dns_packet_count, &iph->saddr, &iph->daddr, domain);

        if (domain_in_blacklist(domain)) {
            printk(KERN_INFO "[M4-Advanced] BLOCKED domain: %s from %pI4 to %pI4\n",
                   domain, &iph->saddr, &iph->daddr);
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

// Netfilter hook template
static const struct nf_hook_ops m4_nf_hook_template = {
    .hook = m4_nf_callback,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops *m4_nf_hook_ops(struct net *net) {
    struct m4_netns_data *netns_data = net_generic(net, m4_net_id);
    return &netns_data->nf_hops;
}

static int __net_init m4_netns_init(struct net *net) {
    struct nf_hook_ops *ops = m4_nf_hook_ops(net);
    memcpy(ops, &m4_nf_hook_template, sizeof(*ops));
    return nf_register_net_hook(net, ops);
}

static void __net_exit m4_netns_exit(struct net *net) {
    struct nf_hook_ops *ops = m4_nf_hook_ops(net);
    nf_unregister_net_hook(net, ops);
}

static struct pernet_operations m4_netns_ops = {
    .init = m4_netns_init,
    .exit = m4_netns_exit,
    .id = &m4_net_id,
    .size = sizeof(struct m4_netns_data),
};

static int __init m4_init(void) {
    int rc = register_pernet_subsys(&m4_netns_ops);
    if (rc) {
        printk(KERN_ERR "[M4-Advanced] Failed to register pernet ops\n");
        return rc;
    }
    printk(KERN_INFO "[M4-Advanced] Module loaded.\n");
    return 0;
}

static void __exit m4_exit(void) {
    unregister_pernet_subsys(&m4_netns_ops);
    printk(KERN_INFO "[M4-Advanced] Module unloaded.\n");
}

module_init(m4_init);
module_exit(m4_exit);

