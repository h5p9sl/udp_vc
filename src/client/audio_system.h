/*! \file audio_system.h
 * \brief The client audio system, responsible for encoding, recording, and
 * playback.
 */

#ifndef _AUDIO_SYSTEM_H_

void audiosystem_init();
void audiosystem_free();

void audiosystem_feed_opus(const unsigned char *opus_data,
                           const unsigned short len,
                           const unsigned int user_id);

/*! \brief If recorded audio is encoded and ready to be sent off, this function
 * returns and consumes the first available buffer filled with Opus encoded
 * data.
 *
 * This function passes ownership of the opus to the caller, therefore note
 * that **the user is responsible** for freeing the returned opus data.
 *
 * \param opus_data A reference to a pointer that will store the address to the
 * opus data given by this function.
 *
 * \param length A reference to a number that will store the length of the opus
 * data.
 *
 * \returns The length parameter, which is non-zero if valid data was encoded
 * and returned. If zero is returned, there is no data ready. If a negative
 * number is returned, an error has occurred.
 */
int audiosystem_get_opus(unsigned char **opus_data, unsigned short *length);

#endif
