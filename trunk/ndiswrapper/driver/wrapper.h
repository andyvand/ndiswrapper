#ifndef WRAPPER_H
#define WRAPPER_H


#include <linux/ioctl.h>

struct put_driver {
	size_t size;
};
                                                                                                                                                                                                                                   
#define WDIOC_PUTDRIVER	_IOWR('N', 0, struct put_driver)
#define WDIOC_TEST	_IOWR('N', 1, int)

#endif /* WRAPPER_H */
