typedef struct {
    int ifin, ifout;
    unsigned int daddr, saddr;
} BNode;

static unsigned int parse_ip(char *p) {
    int k, i=0, b;
    unsigned int ip=0;
    for (k=0; k<4; k++) {
        b=0;
        if (p[i]<'0'||p[i]>'9') return 0;
        while(p[i]>='0'&&p[i]<='9') {
            b=b*10+p[i++]-'0';
            if (b>256) return 0;
        }
        if (k<3&&p[i]!='.') return 0;
        if (k==3&&p[i]!=0) return 0;
        ip = ip | (b<<(k*8));
        i++;
    }
    return ip;
}
