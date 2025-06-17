#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adriano");
MODULE_DESCRIPTION("M4 - DNS Packet Inspector (IPv4)");
MODULE_VERSION("1.0");

static struct nf_hook_ops m4_nfho;

static unsigned int m4_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    udph = udp_hdr(skb);
    if (!udph)
        return NF_ACCEPT;

    if (ntohs(udph->dest) == 53 || ntohs(udph->source) == 53) {
        printk(KERN_INFO "[M4-Base] DNS packet from %pI4 to %pI4\n",
               &iph->saddr, &iph->daddr);
    }

    return NF_ACCEPT;
}

static int __init m4_init(void)
{
    m4_nfho.hook = m4_hookfn;
    m4_nfho.hooknum = NF_INET_PRE_ROUTING;
    m4_nfho.pf = PF_INET;
    m4_nfho.priority = NF_IP_PRI_FIRST;

    int ret = nf_register_net_hook(&init_net, &m4_nfho);
    if (ret) {
        printk(KERN_ERR "[M4-Base] Failed to register netfilter hook.\n");
        return ret;
    }

    printk(KERN_INFO "[M4-Base] Module loaded.\n");
    return 0;
}

static void __exit m4_exit(void)
{
    nf_unregister_net_hook(&init_net, &m4_nfho);
    printk(KERN_INFO "[M4-Base] Module unloaded.\n");
}

module_init(m4_init);
module_exit(m4_exit);

