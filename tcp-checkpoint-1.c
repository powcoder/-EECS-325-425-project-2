/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software withsend specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>

/* checkpoint 1 */
int chitcpd_tcp_send_packet(serverinfo_t *si, chisocketentry_t *entry, const uint8_t *buf, size_t len, int seq);
int chitcpd_tcp_send_ack(serverinfo_t *si, chisocketentry_t *entry);
int chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry);


void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
}


int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
	/* checkpoint 1 */
        /* Your code goes here */
	tcp_packet_t *packet = malloc(sizeof(tcp_packet_t));
        tcphdr_t *header;
        tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

	srand(time(NULL) + (unsigned long int)tcp_data);
        tcp_data->ISS = (rand() % 256) * 1000000;
        tcp_data->SND_UNA = tcp_data->ISS;
        tcp_data->SND_NXT = tcp_data->ISS + 1;
	tcp_data->RCV_WND = TCP_BUFFER_SIZE;


	chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        header = TCP_PACKET_HEADER(packet);

        header->seq = chitcp_htonl(tcp_data->ISS);
        header->ack_seq = 0;
        header->syn = 1;
        header->win = chitcp_htons(tcp_data->RCV_WND);

        chilog(DEBUG, "Sending TCP packet");
        chilog_tcp(DEBUG, packet, LOG_OUTBOUND);
        chitcpd_send_tcp_packet(si, entry, packet);

	chitcpd_update_tcp_state(si, entry, SYN_SENT);
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
	/* checkpoint 1 */
	chitcpd_tcp_handle_packet(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
	/* checkpoint 1 */
	chitcpd_tcp_handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
	/* checkpoint 1 */
	chitcpd_tcp_handle_packet(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND)
    {
        /* Your code goes here */
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else if (event == TIMEOUT_PST)
    {
        /* Your code goes here */
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

/* checkpoint 1 */
int chitcpd_tcp_handle_packet(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *packet = NULL;

    pthread_mutex_lock(&(tcp_data->lock_pending_packets));
    if(tcp_data->pending_packets)
    {
        packet = tcp_data->pending_packets->packet;
        chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    }
    pthread_mutex_unlock(&(tcp_data->lock_pending_packets));

    if (packet == NULL)
    {
        chilog(WARNING, "No pending packets found.");
        return CHITCP_OK;
    }

    chilog(DEBUG, "Processing TCP packet");
    chilog_tcp(DEBUG, packet, LOG_INBOUND);

    tcphdr_t* header = TCP_PACKET_HEADER(packet);
    /* We don't support TCP options */
    if (header->doff != 5)
    {
        chilog(WARNING, "Received unknown TCP option.");
    }

    if (entry->tcp_state == LISTEN)
    {
        /* At this point, we should be receiving the SYN packet
         * from the active peer. We first check for unexpected
         * flags*/
        if (header->rst)
        {
            /* We don't support RST, but the TCP standard says we should
             * just ignore it anyway */
            chilog(WARNING, "In LISTEN state, received a RST packet.");
            return CHITCP_OK;
        }
        if (header->fin)
        {
            chilog(WARNING, "In LISTEN state, received a FIN packet.");
            return CHITCP_OK;
        }
        else if(header->ack)
        {
            /* Should send a RST. We simply ignore it */
            chilog(WARNING, "In LISTEN state, received an ACK packet.");
            return CHITCP_OK;
        }
        else if (header->syn)
        {
            /* Initialize send sequence variables */
            srand(time(NULL) + (unsigned long int)tcp_data);
            tcp_data->ISS = (rand() % 256) * 1000000;
            tcp_data->SND_UNA = tcp_data->ISS;
            tcp_data->SND_NXT = tcp_data->ISS + 1;
            tcp_data->SND_WND = chitcp_ntohs(header->win);

            /* Initialize receive sequence variables */
            tcp_data->IRS = chitcp_ntohl(header->seq);
            tcp_data->RCV_NXT = tcp_data->IRS+1;
	    tcp_data->RCV_WND = TCP_BUFFER_SIZE;

            /* Send SYN/ACK packet (2nd in 3-way handshake) */
            tcp_packet_t *synack_packet = malloc(sizeof(tcp_packet_t));
            tcphdr_t *synack_header;

            chitcpd_tcp_packet_create(entry, synack_packet, NULL, 0);
            synack_header = TCP_PACKET_HEADER(synack_packet);

            synack_header->seq = chitcp_htonl(tcp_data->ISS);
            synack_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            synack_header->syn = 1;
            synack_header->ack = 1;
            synack_header->win = chitcp_htons(tcp_data->RCV_WND);

            chilog(DEBUG, "Sending TCP packet");
            chilog_tcp(DEBUG, synack_packet, LOG_OUTBOUND);
            chitcpd_send_tcp_packet(si, entry, synack_packet);

            chitcpd_update_tcp_state(si, entry, SYN_RCVD);

            return CHITCP_OK;
        }
    }
    if (entry->tcp_state == SYN_SENT)
    {
        if (header->fin)
        {
            chilog(WARNING, "In LISTEN state, received a FIN packet.");
            return CHITCP_OK;
        }
        if (header->ack)
        {
            if (SEG_ACK(packet) <= tcp_data->ISS || SEG_ACK(packet) > tcp_data->SND_NXT)
            {
                chilog(WARNING, "In SYN_SENT state, package has invalid ACK.");
                return CHITCP_OK;
            }
        }
        if (header->rst)
        {
            chilog(WARNING, "In SYN_SENT state, received RST.");
            return CHITCP_OK;
        }
        if (header->syn && !header->ack)
        {
            /* We don't support this transition */
            chilog(WARNING, "In SYN_SENT state, received a SYN without ACK.");
            return CHITCP_OK;
        }
       if (header->syn && header->ack)
        {
            /* We set our send window to the advertised window */
            tcp_data->SND_WND = SEG_WND(packet);

            /* We update the receive sequence variables */
            tcp_data->IRS = SEG_SEQ(packet);
            tcp_data->SND_UNA = SEG_ACK(packet);
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;

            /* Check whether our SYN was acknowledged */
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                /* We send an ACK packet (3rd in the 3-way handshake) */
                chitcpd_tcp_send_ack(si, entry);

                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }

            return CHITCP_OK;
        }
    }

    /* first check sequence number */
    bool_t acceptable = FALSE;

    if(SEG_LEN(packet) == 0 && tcp_data->RCV_WND == 0)
        acceptable = (SEG_SEQ(packet) == tcp_data->RCV_NXT);
    else if (SEG_LEN(packet) == 0 && tcp_data->RCV_WND > 0)
        acceptable = (tcp_data->RCV_NXT  <= SEG_SEQ(packet) && SEG_SEQ(packet) < tcp_data->RCV_NXT + tcp_data->RCV_WND);
    else if (SEG_LEN(packet) > 0 && tcp_data->RCV_WND == 0)
        acceptable = FALSE;
    else if (SEG_LEN(packet) > 0 && tcp_data->RCV_WND > 0)
        acceptable = (tcp_data->RCV_NXT  <= SEG_SEQ(packet) && SEG_SEQ(packet) < tcp_data->RCV_NXT + tcp_data->RCV_WND)
                     ||
                     (tcp_data->RCV_NXT  <= SEG_SEQ(packet) + SEG_LEN(packet) - 1
                      && SEG_SEQ(packet) + SEG_LEN(packet) - 1 < tcp_data->RCV_NXT + tcp_data->RCV_WND);

    if(!acceptable)
    {
        chilog(WARNING, "Segment is not acceptable but still sending ACK.");
        chitcpd_tcp_send_ack(si, entry);
        return CHITCP_OK;
    }
    if(SEG_SEQ(packet) != tcp_data->RCV_NXT)
    {
        /* Not yet supported */
        chilog(WARNING, "Packet with SEG.SEQ=%i is out of order (RCV.NXT=%i)", SEG_SEQ(packet), tcp_data->RCV_NXT);
        return CHITCP_OK;
    }

    if(SEG_LEN(packet) > tcp_data->RCV_WND)
    {
        chilog(WARNING, "Received a packet that doesn't fit in the receive window.");
    }


    /* second check the RST bit, */
    if(header->rst)
    {
        chilog(WARNING, "Received an RST packet.");
        return CHITCP_OK;
    }


    /* third check security and precedence */
    /* Ignored in chiTCP */
    /* fourth, check the SYN bit, */

    if(header->syn)
    {
        chilog(WARNING, "Received a SYN packet, but did not expect one.");
        return CHITCP_OK;
    }


    /* fifth check the ACK field, */

    if(!header->ack)
    {
        chilog(WARNING, "Received a packet without an ACK flag.");
        return CHITCP_OK;
    }
    if(header->ack)
    {
        bool_t state_to_established = FALSE;

        if(entry->tcp_state == SYN_RCVD)
        {
            /* Check for correct acknowledgement number */
            if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <= tcp_data->SND_NXT)
            {
                state_to_established = TRUE;
            }
            else
            {
                chilog(WARNING, "Received incorrect acknowledgement in SYN_RCVD.");
                return CHITCP_OK;
            }
        }
	if((entry->tcp_state == SYN_RCVD && state_to_established) ||
	    entry->tcp_state == ESTABLISHED)
        {
            if (tcp_data->SND_UNA < SEG_ACK(packet) && SEG_ACK(packet) <= tcp_data->SND_NXT)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
                tcp_data->SND_WND = SEG_WND(packet);
                if(state_to_established)
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
            }
            else if (SEG_ACK(packet) < tcp_data->SND_UNA)
            {
                /* Not yet supported */
                chilog(WARNING, "Received duplicate packet.");
                return CHITCP_OK;
            }
            else if (SEG_ACK(packet) < tcp_data->SND_UNA)
            {
                /* Not yet supported */
                chilog(WARNING, "Received out-of-order packet.");
                return CHITCP_OK;
            }
        }
    }

    /* sixth, check the URG bit, */
    if(header->urg)
    {
        chilog(WARNING, "Received a packet with an URG flag");
        return CHITCP_OK;
    }

    chitcp_tcp_packet_free(packet);
    free(packet);

    return CHITCP_OK;
}

/* checkpoint 1 */
int chitcpd_tcp_send_ack(serverinfo_t *si, chisocketentry_t *entry)
{
    return chitcpd_tcp_send_packet(si, entry, NULL, 0, 0);
}

/* checkpoint 1 */
int chitcpd_tcp_send_packet(serverinfo_t *si, chisocketentry_t *entry, const uint8_t *buf, size_t len, int seq)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    /* Create packet */
    tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *header;

    chitcpd_tcp_packet_create(entry, packet, buf, len);

    /* Fill send header */
    header = TCP_PACKET_HEADER(packet);
    header->seq = chitcp_htonl(tcp_data->SND_NXT);
    header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    header->ack = 1;
    header->win = chitcp_htons(tcp_data->RCV_WND);

    chilog(DEBUG, "Sending TCP packet");
    /* Send packet */
    chitcpd_send_tcp_packet(si, entry, packet);

    if(len <= 0)
    {
        chitcp_tcp_packet_free(packet);
        free(packet);
    }
    tcp_data->SND_NXT += len;

    return CHITCP_OK;
}



