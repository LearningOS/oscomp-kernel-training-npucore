#![allow(unused)]
pub const SUCCESS: isize = 0;
pub const EPERM: isize = -1;
pub const ENOENT: isize = -2;
pub const ESRCH: isize = -3;
pub const EINTR: isize = -4;
pub const EIO: isize = -5;
pub const ENXIO: isize = -6;
pub const E2BIG: isize = -7;
pub const ENOEXEC: isize = -8;
pub const EBADF: isize = -9;
pub const ECHILD: isize = -10;
pub const EAGAIN: isize = -11;
pub const ENOMEM: isize = -12;
pub const EACCES: isize = -13;
pub const EFAULT: isize = -14;
pub const ENOTBLK: isize = -15;
pub const EBUSY: isize = -16;
pub const EEXIST: isize = -17;
pub const EXDEV: isize = -18;
pub const ENODEV: isize = -19;
pub const ENOTDIR: isize = -20;
pub const EISDIR: isize = -21;
pub const EINVAL: isize = -22;
pub const ENFILE: isize = -23;
pub const EMFILE: isize = -24;
pub const ENOTTY: isize = -25;
pub const ETXTBSY: isize = -26;
pub const EFBIG: isize = -27;
pub const ENOSPC: isize = -28;
pub const ESPIPE: isize = -29;
pub const EROFS: isize = -30;
pub const EMLINK: isize = -31;
pub const EPIPE: isize = -32;
pub const EDOM: isize = -33;
pub const ERANGE: isize = -34;
pub const EDEADLK: isize = -35;
pub const ENAMETOOLONG: isize = -36;
pub const ENOLCK: isize = -37;
pub const ENOSYS: isize = -38;
pub const ENOTEMPTY: isize = -39;
pub const ELOOP: isize = -40;
pub const EWOULDBLOCK: isize = EAGAIN;
pub const ENOMSG: isize = -42;
pub const EIDRM: isize = -43;
pub const ECHRNG: isize = -44;
pub const EL2NSYNC: isize = -45;
pub const EL3HLT: isize = -46;
pub const EL3RST: isize = -47;
pub const ELNRNG: isize = -48;
pub const EUNATCH: isize = -49;
pub const ENOCSI: isize = -50;
pub const EL2HLT: isize = -51;
pub const EBADE: isize = -52;
pub const EBADR: isize = -53;
pub const EXFULL: isize = -54;
pub const ENOANO: isize = -55;
pub const EBADRQC: isize = -56;
pub const EBADSLT: isize = -57;
pub const EDEADLOCK: isize = EDEADLK;
pub const EBFONT: isize = -59;
pub const ENOSTR: isize = -60;
pub const ENODATA: isize = -61;
pub const ETIME: isize = -62;
pub const ENOSR: isize = -63;
pub const ENONET: isize = -64;
pub const ENOPKG: isize = -65;
pub const EREMOTE: isize = -66;
pub const ENOLINK: isize = -67;
pub const EADV: isize = -68;
pub const ESRMNT: isize = -69;
pub const ECOMM: isize = -70;
pub const EPROTO: isize = -71;
pub const EMULTIHOP: isize = -72;
pub const EDOTDOT: isize = -73;
pub const EBADMSG: isize = -74;
pub const EOVERFLOW: isize = -75;
pub const ENOTUNIQ: isize = -76;
pub const EBADFD: isize = -77;
pub const EREMCHG: isize = -78;
pub const ELIBACC: isize = -79;
pub const ELIBBAD: isize = -80;
pub const ELIBSCN: isize = -81;
pub const ELIBMAX: isize = -82;
pub const ELIBEXEC: isize = -83;
pub const EILSEQ: isize = -84;
pub const ERESTART: isize = -85;
pub const ESTRPIPE: isize = -86;
pub const EUSERS: isize = -87;
pub const ENOTSOCK: isize = -88;
pub const EDESTADDRREQ: isize = -89;
pub const EMSGSIZE: isize = -90;
pub const EPROTOTYPE: isize = -91;
pub const ENOPROTOOPT: isize = -92;
pub const EPROTONOSUPPORT: isize = -93;
pub const ESOCKTNOSUPPORT: isize = -94;
pub const EOPNOTSUPP: isize = -95;
pub const ENOTSUP: isize = EOPNOTSUPP;
pub const EPFNOSUPPORT: isize = -96;
pub const EAFNOSUPPORT: isize = -97;
pub const EADDRINUSE: isize = -98;
pub const EADDRNOTAVAIL: isize = -99;
pub const ENETDOWN: isize = -100;
pub const ENETUNREACH: isize = -101;
pub const ENETRESET: isize = -102;
pub const ECONNABORTED: isize = -103;
pub const ECONNRESET: isize = -104;
pub const ENOBUFS: isize = -105;
pub const EISCONN: isize = -106;
pub const ENOTCONN: isize = -107;
pub const ESHUTDOWN: isize = -108;
pub const ETOOMANYREFS: isize = -109;
pub const ETIMEDOUT: isize = -110;
pub const ECONNREFUSED: isize = -111;
pub const EHOSTDOWN: isize = -112;
pub const EHOSTUNREACH: isize = -113;
pub const EALREADY: isize = -114;
pub const EINPROGRESS: isize = -115;
pub const ESTALE: isize = -116;
pub const EUCLEAN: isize = -117;
pub const ENOTNAM: isize = -118;
pub const ENAVAIL: isize = -119;
pub const EISNAM: isize = -120;
pub const EREMOTEIO: isize = -121;
pub const EDQUOT: isize = -122;
pub const ENOMEDIUM: isize = -123;
pub const EMEDIUMTYPE: isize = -124;
pub const ECANCELED: isize = -125;
pub const ENOKEY: isize = -126;
pub const EKEYEXPIRED: isize = -127;
pub const EKEYREVOKED: isize = -128;
pub const EKEYREJECTED: isize = -129;
pub const EOWNERDEAD: isize = -130;
pub const ENOTRECOVERABLE: isize = -131;
pub const ERFKILL: isize = -132;
pub const EHWPOISON: isize = -133;

#[macro_export]
macro_rules! set_errno {
    ($errno:expr) => {};
}

#[macro_export]
macro_rules! errno_exit {
    ($errno:expr) => {
	set_errno!($errno)!;
        return expr;// or -1?
    };
}
