#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - DNS Packet Inspector - Base");

static struct nf_hook_ops nfho;

static unsigned int dns_base_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct udphdr *udph;

    // Sanity check
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // We only care about UDP packets
    if (iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    // Make sure the skb has enough data
    if (skb_linearize(skb) != 0)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (!udph)
        return NF_ACCEPT;

    // Match DNS packets (UDP port 53)
    if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) {
        printk(KERN_INFO "[M4-Base] DNS packet from %pI4 to %pI4\n",
               &iph->saddr, &iph->daddr);
    }

    return NF_ACCEPT;
}

static int __init dns_base_init(void) {
    nfho.hook = dns_base_hook;
    nfho.hooknum = NF_INET_FORWARD;     // Use FORWARD hook
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    int ret = nf_register_net_hook(&init_net, &nfho);
    if (ret != 0) {
        printk(KERN_ERR "[M4-Base] Failed to register net hook.\n");
        return ret;
    }

    printk(KERN_INFO "[M4-Base] Module loaded.\n");
    return 0;
}

static void __exit dns_base_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[M4-Base] Module unloaded.\n");
}

module_init(dns_base_init);
module_exit(dns_base_exit);

