#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/errno.h>
#include <net/9p/9p.h>

/**
 * struct errormap - 将Plan 9的字符串错误映射到Linux数字ID
 * @name: 通过9P协议发送的字符串
 * @val: 最接近代表@name的数字ID
 * @namelen: 字符串长度
 * @list: 用于字符串查找的哈希表列表
 */
struct errormap {
	char *name;
	int val;

	int namelen;
	struct hlist_node list;
};

#define ERRHASHSZ		32
static struct hlist_head hash_errmap[ERRHASHSZ];

/* 修正 - 减少到合理的大小 */
static struct errormap errmap[] = {
	{"操作不被允许", EPERM},
	{"wstat被禁止", EPERM},
	{"没有此文件或目录", ENOENT},
	{"找不到目录条目", ENOENT},
	{"找不到文件", ENOENT},
	{"系统调用被中断", EINTR},
	{"输入/输出错误", EIO},
	{"没有此设备或地址", ENXIO},
	{"参数列表过长", E2BIG},
	{"错误的文件描述符", EBADF},
	{"资源暂时不可用", EAGAIN},
	{"无法分配内存", ENOMEM},
	{"权限被拒绝", EACCES},
	{"错误的地址", EFAULT},
	{"需要块设备", ENOTBLK},
	{"设备或资源忙", EBUSY},
	{"文件已存在", EEXIST},
	{"无效的跨设备链接", EXDEV},
	{"没有此设备", ENODEV},
	{"不是目录", ENOTDIR},
	{"是一个目录", EISDIR},
	{"无效参数", EINVAL},
	{"系统打开文件过多", ENFILE},
	{"打开文件过多", EMFILE},
	{"文本文件忙", ETXTBSY},
	{"文件过大", EFBIG},
	{"设备上没有剩余空间", ENOSPC},
	{"非法定位", ESPIPE},
	{"只读文件系统", EROFS},
	{"链接过多", EMLINK},
	{"管道破裂", EPIPE},
	{"数值参数超出域", EDOM},
	{"数值结果超出范围", ERANGE},
	{"避免资源死锁", EDEADLK},
	{"文件名过长", ENAMETOOLONG},
	{"没有可用的锁", ENOLCK},
	{"功能未实现", ENOSYS},
	{"目录不为空", ENOTEMPTY},
	{"符号链接层次过多", ELOOP},
	{"没有所需类型的消息", ENOMSG},
	{"标识符已删除", EIDRM},
	{"没有可用数据", ENODATA},
	{"机器不在网络上", ENONET},
	{"包未安装", ENOPKG},
	{"对象是远程的", EREMOTE},
	{"链接已断开", ENOLINK},
	{"发送时通信错误", ECOMM},
	{"协议错误", EPROTO},
	{"错误消息", EBADMSG},
	{"文件描述符状态错误", EBADFD},
	{"流管道错误", ESTRPIPE},
	{"用户过多", EUSERS},
	{"在非套接字上进行套接字操作", ENOTSOCK},
	{"消息过长", EMSGSIZE},
	{"协议不可用", ENOPROTOOPT},
	{"协议不支持", EPROTONOSUPPORT},
	{"套接字类型不支持", ESOCKTNOSUPPORT},
	{"操作不支持", EOPNOTSUPP},
	{"协议族不支持", EPFNOSUPPORT},
	{"网络已关闭", ENETDOWN},
	{"网络不可达", ENETUNREACH},
	{"网络在重置时断开连接", ENETRESET},
	{"软件导致连接中止", ECONNABORTED},
	{"连接被对端重置", ECONNRESET},
	{"没有可用的缓冲区空间", ENOBUFS},
	{"传输端点已连接", EISCONN},
	{"传输端点未连接", ENOTCONN},
	{"传输端点关闭后无法发送", ESHUTDOWN},
	{"连接超时", ETIMEDOUT},
	{"连接被拒绝", ECONNREFUSED},
	{"主机已关闭", EHOSTDOWN},
	{"没有到主机的路由", EHOSTUNREACH},
	{"操作已在进行中", EALREADY},
	{"操作正在进行中", EINPROGRESS},
	{"是一个命名类型文件", EISNAM},
	{"远程I/O错误", EREMOTEIO},
	{"磁盘配额超限", EDQUOT},
/* 来自fossil、vacfs和u9fs的错误 */
	{"fid未知或超出范围", EBADF},
	{"权限被拒绝", EACCES},
	{"文件不存在", ENOENT},
	{"认证失败", ECONNREFUSED},
	{"目录读取中的错误偏移", ESPIPE},
	{"fid使用错误", EBADF},
	{"wstat无法在文件和目录间转换", EPERM},
	{"目录不为空", ENOTEMPTY},
	{"文件已存在", EEXIST},
	{"文件已经存在", EEXIST},
	{"文件或目录已存在", EEXIST},
	{"fid已在使用中", EBADF},
	{"文件使用中", ETXTBSY},
	{"i/o错误", EIO},
	{"文件已打开进行I/O", ETXTBSY},
	{"非法模式", EINVAL},
	{"非法名称", ENAMETOOLONG},
	{"不是目录", ENOTDIR},
	{"不是建议组的成员", EPERM},
	{"不是所有者", EACCES},
	{"只有所有者可以在wstat中更改组", EACCES},
	{"只读文件系统", EROFS},
	{"无法访问特殊文件", EPERM},
	{"i/o计数过大", EIO},
	{"未知组", EINVAL},
	{"未知用户", EINVAL},
	{"虚假的wstat缓冲区", EPROTO},
	{"独占使用文件已打开", EAGAIN},
	{"损坏的目录条目", EIO},
	{"损坏的文件条目", EIO},
	{"损坏的块标签", EIO},
	{"损坏的元数据", EIO},
	{"非法偏移", EINVAL},
	{"非法路径元素", ENOENT},
	{"文件系统根目录已损坏", EIO},
	{"损坏的超级块", EIO},
	{"协议错误", EPROTO},
	{"文件系统已满", ENOSPC},
	{"文件正在使用中", EAGAIN},
	{"目录条目未分配", ENOENT},
	{"文件为只读", EROFS},
	{"文件已被删除", EIDRM},
	{"仅支持截断到零长度", EPERM},
	{"无法删除根目录", EPERM},
	{"文件过大", EFBIG},
	{"venti i/o错误", EIO},
	/* 这些不是错误 */
	{"u9fs rhostsauth: 不需要认证", 0},
	{"u9fs authnone: 不需要认证", 0},
	{NULL, -1}
};

/**
 * p9_error_init - 将映射预加载到哈希列表中
 *
 */

int p9_error_init(void)
{
	struct errormap *c;
	int bucket;

	/* 初始化哈希表 */
	for (bucket = 0; bucket < ERRHASHSZ; bucket++)
		INIT_HLIST_HEAD(&hash_errmap[bucket]);

	/* 将初始错误映射加载到哈希表中 */
	for (c = errmap; c->name != NULL; c++) {
		c->namelen = strlen(c->name);
		bucket = jhash(c->name, c->namelen, 0) % ERRHASHSZ;
		INIT_HLIST_NODE(&c->list);
		hlist_add_head(&c->list, &hash_errmap[bucket]);
	}

	return 1;
}
EXPORT_SYMBOL(p9_error_init);

/**
 * errstr2errno - 将错误字符串转换为错误编号
 * @errstr: 错误字符串
 * @len: 错误字符串长度
 *
 */

int p9_errstr2errno(char *errstr, int len)
{
	int errno;
	struct errormap *c;
	int bucket;

	errno = 0;
	c = NULL;
	bucket = jhash(errstr, len, 0) % ERRHASHSZ;
	hlist_for_each_entry(c, &hash_errmap[bucket], list) {
		if (c->namelen == len && !memcmp(c->name, errstr, len)) {
			errno = c->val;
			break;
		}
	}

	if (errno == 0) {
		/* TODO: 如果找不到错误，动态添加它 */
		errstr[len] = 0;
		pr_err("%s: 服务器报告未知错误 %s\n",
		       __func__, errstr);
		errno = ESERVERFAULT;
	}

	return -errno;
}
EXPORT_SYMBOL(p9_errstr2errno);
