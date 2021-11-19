#pragma once

struct EncodedDataBuffer {
    uint16_t length;
    uint8_t data[64];
};

uint8_t gen_checksum(void* data, size_t length) {
    uint8_t sum;
    for (size_t i = 0; i < length; i++) {
        sum ^= ((uint8_t*)data)[i];
    }
    return sum;
}

int verify_checksum(void* data, size_t length, uint8_t sum) {
    return (int)gen_checksum(data, length) - (int)sum;
}

/* Receive whole voice packet from remote */
int receive_vc_data(
	int vcsock,
	struct EncodedDataBuffer* out,
    struct sockaddr_storage* addr,
    socklen_t* addrlen
) {
	struct EncodedDataBuffer data;
	ssize_t r, read;
	int data_len;

	memset(&data, 0, sizeof data);

	/* read until entire packet is received
	note that this blocks the current thread. */

	r = recvfrom(vcsock,
		&data.length,
		sizeof(data.length),
		0, (struct sockaddr*)addr, addrlen);
	if (r < 0) return r;

    data_len = ntohs(data.length);
	data.length = data_len;

	assert(data.length != 0);

	while (0 < (r = recvfrom(vcsock,
			&data.data,
			data_len - read,
			0, (struct sockaddr*)addr, addrlen))) {
		read += r;
        if (read == data_len) break;
	}
	if (r <= 0) return r;

    printf("%i == %li\n", data_len, read);
	assert(data_len == read);

	memcpy(out, &data, sizeof data);

	return data_len;
}

/* Send whole voice packet to remote */
ssize_t send_vc_data(
	int vcsock,
	struct EncodedDataBuffer* data,
	struct sockaddr* addr,
	socklen_t addrlen
) {
    uint16_t data_len;
	ssize_t s, sent;

	/* sendto() until entire packet is sent
	note that this blocks the current thread. */

	assert(data->length != 0);

	data_len = htons(data->length);

	s = sendto(vcsock,
		&data_len,
		sizeof(data->length),
		0, addr, addrlen);
	if (s <= 0) return s;

	while (0 < (s = sendto(vcsock,
			&data->data,
			data->length - sent,
			0, addr, addrlen))) {
		sent += s;
        if (sent == data->length) break;
	}
	if (s <= 0) return s;

	assert(data->length == sent);

	return sent;
}