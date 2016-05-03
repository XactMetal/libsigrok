/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2016 Lars-Peter Clausen <lars@metafoo.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#ifdef G_OS_WIN32

SR_PRIV struct sr_event *sr_event_new(void)
{
	HANDLE event;

	return (struct sr_event *)CreateEvent(NULL, TRUE, FALSE, NULL);
}

SR_PRIV void sr_event_free(struct sr_event *event)
{
	CloseHandle((HANDLE)event);
}

SR_PRIV void sr_event_signal(struct sr_event *event)
{
	SetEvent((HANDLE)event);
}

SR_PRIV void sr_event_ack(struct sr_event *event)
{
	ResetEvent((HANDLE)event);
}

static void sr_event_get_pollfd(struct sr_event *event,
	GPollFD *pollfd)
{
	pollfd->fd = (gintptr)event;
	pollfd->events = G_IO_IN;
}

#else

#include <errno.h>
#include <unistd.h>

#ifdef HAVE_EVENTFD /* FIXME */

#include <sys/eventfd.h>

struct sr_event {
	int fd;
};

SR_PRIV struct sr_event *sr_event_new(void)
{
	struct sr_event *event;

	event = g_slice_new(struct sr_event);
	if (!event)
		return NULL;

	event->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (event->fd < 0)
		return NULL;

	return event;
}

SR_PRIV void sr_event_free(struct sr_event *event)
{
	close(event->fd);
	g_slice_free(struct sr_event, event);
}

SR_PRIV void sr_event_signal(struct sr_event *event)
{
	eventfd_t e = 1;
	int ret;

	do {
		ret = write(event->fd, &e, sizeof(e));
	} while (ret == -1 && errno == EINTR);
}

SR_PRIV void sr_event_ack(struct sr_event *event)
{
	eventfd_t e;
	int ret;

	do {
		ret = read(event->fd, &e, sizeof(e));
	} while (ret == -1 && errno == EINTR);
}

static void sr_event_get_pollfd(struct sr_event *event,
	GPollFD *pollfd)
{
	pollfd->fd = (gintptr)event->fd;
	pollfd->events = G_IO_IN;
}

#else

#include <fcntl.h>
#include <glib-unix.h>

struct sr_event {
	int fd[2];
};

SR_PRIV struct sr_event *sr_event_new(void)
{
	struct sr_event *event;

	event = g_slice_new(struct sr_event);
	if (!event)
		return NULL;

	g_unix_open_pipe(event->fd, FD_CLOEXEC, NULL);
	g_unix_set_fd_nonblocking(event->fd[0], TRUE, NULL);
	g_unix_set_fd_nonblocking(event->fd[1], TRUE, NULL);

	return event;
}

SR_PRIV void sr_event_free(struct sr_event *event)
{
	close(event->fd[0]);
	close(event->fd[1]);
	g_slice_free(struct sr_event, event);
}

SR_PRIV void sr_event_signal(struct sr_event *event)
{
	char e = 1;
	int ret;

	do {
		ret = write(event->fd[1], &e, sizeof(e));
	} while (ret == -1 && errno == EINTR);
}

SR_PRIV void sr_event_ack(struct sr_event *event)
{
	char e;
	int ret;

	do {
		ret = read(event->fd[0], &e, sizeof(e));
	} while ((ret == -1 && errno == EINTR) || ret > 0);
}

static void sr_event_get_pollfd(struct sr_event *event,
	GPollFD *pollfd)
{
	pollfd->fd = (gintptr)event->fd[0];
	pollfd->events = G_IO_IN;
}

#endif

#endif

struct sr_event_source {
	GSource source;
	GPollFD pollfd;
	struct sr_session *session;
	struct sr_event *event;
};

static gboolean sr_event_source_check(GSource *source)
{
	struct sr_event_source *esource = (struct sr_event_source *)source;
	return esource->pollfd.revents & G_IO_IN;
}

static gboolean sr_event_source_dispatch(GSource *source,
	GSourceFunc callback, void *user_data)
{
	(void)source;

	if (!callback)
		return G_SOURCE_REMOVE;

	return callback(user_data);
}

static void sr_event_source_finalize(GSource *source)
{
	struct sr_event_source *esource = (struct sr_event_source *)source;

	sr_session_source_destroyed(esource->session, esource->event, source);
}

static GSourceFuncs sr_event_source_funcs = {
	.check = sr_event_source_check,
	.dispatch = sr_event_source_dispatch,
	.finalize = sr_event_source_finalize,
};

SR_PRIV int sr_event_source_add(struct sr_session *session,
	struct sr_event *event, GSourceFunc cb, gpointer cb_data)
{
	struct sr_event_source *esource;
	GSource *source;
	int ret;

	source = g_source_new(&sr_event_source_funcs,
		sizeof(struct sr_event_source));
	if (!source)
		return SR_ERR;

	esource = (struct sr_event_source *)source;
	esource->session = session;
	esource->event = event;

	sr_event_get_pollfd(event, &esource->pollfd);
	g_source_add_poll(source, &esource->pollfd);

	g_source_set_name(source, "Event");

	g_source_set_callback(source, (GSourceFunc)cb, cb_data, NULL);

	ret = sr_session_source_add_internal(session, event, source);
	g_source_unref(source);

	return ret;
}

SR_PRIV int sr_event_source_remove(struct sr_session *session,
	struct sr_event *event)
{
	return sr_session_source_remove_internal(session, event);
}
