#ifndef IW_NDIS_H
#define IW_NDIS_H

#include "ndis.h"

extern const struct iw_handler_def ndis_handler_def;

int ndis_set_mode(struct net_device *dev, struct iw_request_info *info,
				  union iwreq_data *wrqu, char *extra);
struct iw_statistics *ndis_get_wireless_stats(struct net_device *dev);

#endif // IW_NDIS_H
