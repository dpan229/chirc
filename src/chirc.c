#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// #include "log.h"

#define MAX_IRC_MESSAGE_LEN 510
#define MAX_IRC_MESSAGE_ARGS 15

typedef struct irc_message irc_message_t;
typedef struct irc_user irc_user_t;
typedef struct user_group user_group_t;
typedef struct channel_group channel_group_t;

/*
 * irc_message - structure to hold parsed messages or build outgoing messages. 
 * Concatenating prefix, type and all of args with spaces in between
 * yields a valid irc message. Function new_message() creates a new message
 * with all pointers to NULL
 *
 * prefix: message prefix, NULL if no prefix. It is stored here without the leading ':'
 *
 * type: message type, either an all caps string (e.g. "NICK") or a numeric code
 *      such as "001" for RPL_WELCOME
 *
 * args: array of all remaining message parameters. Their order and meaning depends
 *      on the message type. All unused array entries should be NULL as set by
 *      new_message()
 *
 * nargs: number of fields of args used by this message
 *
 * longlast: whether last argument is a potentially multword long field. It is stored
 *     without the leading ':'
 */
struct irc_message {
    char *prefix;
    char *type;
    char *args[MAX_IRC_MESSAGE_ARGS];
    int nargs;
    bool longlast;
};

/*
 * irc_user - structure to hold a single user
 */
struct irc_user {
    char *nick;
    char *username;
    channel_group_t channels;
};

/* 
 * user_group - structure to hold all users on the server or all users in a channel.
 * channel_name is NULL if this represents all server users and not a channel.
 * Currently only holds up to a single user
 */
struct user_group {
    char *channel_name;
    /* TODO replace with some data structure holding user pointers */
    irc_user_t *user;
};

/*
 * channel_group - structure to hold a group of users groups, either to hold all
 * channels on the server or all channels a user has joined
 */
struct channel_group {
    /* TODO replace with some data structure holding user_group_t pointers */
    user_group_t *channel;
}

/* may have to malloc in new_user_group and new_channel_group like in new_user? */

channel_group_t new_channel_group() 
{
    channel_group_t channels;
    channels.channel = NULL;
    return channels;
}

user_group_t new_user_group()
{
    user_group_t users;
    users.channel_name = NULL;
    users.user = NULL;
    return users;
}

/*
 * new_user - creates a new irc_user_t with all pointers set to NULL
 */
irc_user_t *new_user()
{
    irc_user_t *user = (irc_user_t *) malloc(sizeof(irc_user_t));
    user->nick = NULL;
    user->username = NULL;
    user->channels = new_channel_group();
    return user;
}

/*
 * new_message - creates a new irc_message_t with all pointers set to NULL
 */
irc_message_t new_message()
{
    irc_message_t message;
    message.prefix = NULL;
    message.type = NULL;
    for (int i = 0; i < MAX_IRC_MESSAGE_ARGS; i++) {
        message.args[i] = NULL;
    }
    message.nargs = 0;
    message.longlast = false;
    return message;
}

/*
 * find_user_by_nick - returns a pointer to a user with the given nick
 *     or NULL if there is no such user
 */
irc_user_t *find_user_by_nick(user_group_t users, char *nick)
{
    /* server is currently structured to hold only 1 user */
    if (users.user && strcmp(users.user->nick, nick) == 0) {
        return users.user;
    }
    return NULL;
}

user_group_t *find_channel_by_name(channel_group_t channels, char *name)
{

}

/*
 * add_user - add a user to the server. Returns 1 if success, 0 if failure
 */
int add_user(user_group_t *users, irc_user_t *user)
{
    /* server is currently structured to hold only 1 user */
    if (users->user) {
        //chilog(ERROR, "Attempted to add user to server at full capacity");
        return 0;
    } else {
        users->user = user;
        return 1;
    }
}

int two_way_add_user_to_channel(user_group_t *channel, irc_user_t *user)
{
    add_user(channel, user);
    add_channel(&user->channels, channel);
    return 1;
}

int two_way_remove_user_from_channel(user_group_t *channel, irc_user_t *user)
{
    remove_user(channel, user);
    remove_channel(&user->channels, channel);
    return 1;
}

int remove_user(user_group_t *users, irc_user_t *user)
{
    /* TODO remove user from structure */
    free(user);
    return 1;
}

int add_channel(clannel_group_t *channels, user_group_t *channel)
{
    /* TODO add channel to the group structure */
    channels.channel = channel;
    return 1;
}

int remove_channel(channel_group_t *channels, user_group_t *users)
{
    /* TODO remove channel from group structure */

}

/*
 * parse_message - takes a string representing a full irc message and creates
 * a new irc_message struct. Will break if total number of arguments after message type
 * is more than MAX_IRC_MESSAGE_ARGS. Input string is modified by strtok_r
 *
 * message: string containing a full irc message
 */
irc_message_t parse_message(char message[])
{
    /* new_message sets prefix and all args entries to NULL and longlast to false */
    irc_message_t parsed_message = new_message();

    char *rest = message;    
    char *token = strtok_r(rest, " ", &rest);
    /* message starts with either prefix (begining with ':') or message type */
    if (token[0] == ':') {
        parsed_message.prefix = strdup(token + 1);
        token = strtok_r(rest, " ", &rest);
    }
    parsed_message.type = strdup(token);

    /* put the rest of the arguments in args. Multiword message body always starts with ':' */
    if (rest[0] == ':') {
        parsed_message.args[0] = strdup(rest + 1);
        parsed_message.longlast = true;
        parsed_message.nargs = 1;
        return parsed_message;
    }
    
    int i = 0;
    while (token = strtok_r(rest, " ", &rest)) {
        parsed_message.args[i] = strdup(token);
        if (rest[0] == ':') {
            parsed_message.args[i + 1] = strdup(rest + 1);
            parsed_message.longlast = true;
            parsed_message.nargs = i + 2;
            return parsed_message;
        }
        i++;
    }
    parsed_message.nargs = i;
    return parsed_message;
}

/*
 * compose_message - creates a string with the contents of the given irc message.
 * The string is created with malloc so should be freed after it is used
 */
char *compose_message(irc_message_t message)
{
    char *outString = malloc(sizeof(char) * MAX_IRC_MESSAGE_LEN);
    if (message.prefix) {
        sprintf(outString, ":%s %s", message.prefix, message.type);
    } else {
        strcpy(outString, message.type);
    }

    for (int i = 0; i < message.nargs - 1; i++) {
        strcat(outString, " ");
        strcat(outString, message.args[i]);
    }
    /* add last argument with leading ':' if it is long */
    if (message.nargs > 0) {
        if (message.longlast) {
            strcat(outString, " :");
        } else {
            strcat(outString, " ");
        }
        strcat(outString, message.args[message.nargs - 1]);
    }
    return outString;
}

int check_num_args(irc_message_t message, int min_args)
{
    if (message.nargs < min_args) {
        /* TODO not enough arguments, send ERR_NEEDMOREPARAMS reply */
        return 0;
    } else {
        return 1;
    }
}

/*
 * handle_message - does the server actions corresponding to the given message
 * coming from the given user
 *
 */
void handle_message(user_group_t *users, channel_group_t *channels, irc_user_t *user, irc_message_t message)
{
    if (strcmp(message.type, "NICK") == 0) {
        /* should be of the form "NICK <nick>" */
        if (message.nargs == 0) {
            /* TODO no nick given, send ERR_NONICKNAMEGIVEN reply */
        } else if (user->username) {
            /* this comes from a registered user, change nick for that user */
            user->nick = strdup(message.args[0]);
            /* TODO send a message to other users of the form ":<old nick>!<user host> NICK <new nick>" */
        } else {
            /* this user is registering */
            user->nick = strdup(message.args[0]);
        }

    } else if (strcmp(message.type, "USER") == 0) {
        /* should be of the form "USER <nick> * * :<username>" */
        if (check_num_args(message, 4)) {
            irc_user_t *user = find_user_by_nick(*users, message.args[0]);
            if (user) {
                if (user->username) {
                    /* TODO this user is already registered, send ERR_ALREADYREGISTERED reply */
                } else {
                    user->username = strdup(message.args[3]);
                    /* TODO send RPL_WELCOME, RPL_YOURHOST, RPL_CREATED and RPL_MYINFO replies */
                }
            } else {
                printf("No user with nick %s\n", message.args[0]);
            }
        }

    } else if (strcmp(message.type, "QUIT") == 0) {
        /* should be of the form "QUIT [:<quit message>]" */ 
        /* quit message defaults to "Client Quit" if not given */
        char *quit_message;
        if (message.nargs > 0) {
            quit_message = message.args[0];
        } else {
            quit_message = "Client Quit";
        }
        /* TODO disconnect this user and send a message to other users of the form ":<nick>!<host> QUIT :<quit message>" */
    
    } else if (strcmp(message.type, "PRIVMSG") == 0 || strcmp(message.type, "NOTICE") == 0) {
        /* should be of the form "PRIVMSG <recipient nick> :<message>" or NOTICE <recipient nick> :<message>" */
        /* TODO add support to send a message to a channel */
        bool is_privmsg = (strcmp(message.type, "PRIVMSG") == 0);
        if (message.nargs == 1) {
            /* message is malformed; don't send error reply if it is a NOTICE */
            if (is_privmsg) {
                if (message.longlast) {
                    /* TODO no recipient given, send ERR_NORECIPIENT reply */
                } else {
                    /* TODO no message text given, send ERR_NOTEXTTOSEND reply */
                }
            }
        } else {
            irc_user_t *recipient = find_user_by_nick(*users, message.args[0]);
            if (recipient) {
                /* TODO send message to recipient of the form ":<nick>!<host> PRIVMSG <recipient nick> :<message>" */
            } else {
                /* don't send an error reply if this is a NOTICE */
                if (is_privmsg) {
                    /* TODO no user with this nickname, send ERR_NOSUCHNICK reply */
                }
            }
        }

    } else if (strcmp(message.type, "PING") == 0) {
        /* ignore parameters in PING, just send PONG response */
        /* TODO send pong response to this user */

    } else if (strcmp(message.type, "PONG") == 0) {
        /* silently ignore this message */

    /* MOTD command not required in specifications */

    } else if (strcmp(message.type, "LUSERS") == 0) {
        /* ignore parameters in LUSERS, always reply with info about the whole server */
        /* TODO send replies in this order: RPL_LUSERCLIENT, RPL_LUSEROP, RPL_LUSERUNKNOWN, RPL_LUSERCHANNELS, RPL_LUSERME */

    } else if (strcmp(message.type, "WHOIS") == 0) {
        /* should be of the form "WHOIS <nick>" */
        /* if WHOIS has no parameters, silently ignore it */
        if (message.nargs > 0) {
            irc_user_t *recipient = find_user_by_nick(*users, message.args[0]);
            if (recipient) {
                /* TODO send replies in this order: RPL_WHOISUSER, RPL_WHOISSERVER, RPL_ENDOFWHOIS */
            } else {
                /* TODO no user with this nick, send ERR_NOSUCHNICK reply */
            }
        }

    } else if (strcmp(message.type, "JOIN") == 0) {
        /* should be of the form "JOIN <channel name>" or "JOIN 0" to leave all channels this user is in */
        if (check_num_args(message, 1)) {
            if (strcmp(message.args[0]), "0") == 0) {

            } else {
                user_group_t *channel = find_channel_by_name(*channels, message.args[0]);
                if (channel) {
                    two_way_add_user_to_channel(channel, user);
                    /* TODO send RPL_NAMEREPLY reply */
                }
            }
        }

    } else if (strcmp(message.type, "PART") == 0) {
        /* should be of the form "PART <channel name> [:<parting message>]" */
        if (check_num_args(message, 1)) {
            if (message.nargs == 1) {
                /* no parting message */
            } else {
                /* with parting message */
            }
        }

    } else if (strcmp(message.type, "LIST") == 0) {

    } else {
        /* TODO unknown command type, send ERR_UNKNOWNCOMMAND reply */
    }
}

int main(int argc, char *argv[])
{
    /* testing examples */

    char message[] = ":mprefix PRIVMSG rory :Hey rory...";
    irc_message_t parsed = parse_message(message);
    printf("prefix: %s type: %s args: %s, %s nargs: %d\n", parsed.prefix, parsed.type, parsed.args[0], parsed.args[1], parsed.nargs);
    char *reconstructed = compose_message(parsed);
    printf("reconstructed: %s\n", reconstructed);
    free(reconstructed);

    user_group_t all_users = new_user_group();
    chennel_group_t all_channels = new_channel_group();
    user_group_t a_channel = new_use_group();
    a_channel.channel_name = "#channel1";
    all_channels.add_channel(&a_channel);

    /* user should be added when a new connection is made */
    irc_user_t *user = new_user();
    add_user(&users, user);

    char message1[] = "NICK myNick";
    char message2[] = "USER myNick * * :My Username";
    handle_message(&users, &channels, user, parse_message(message1));
    handle_message(&users, &channels, user, parse_message(message2));
    printf("nick: %s, username: %s\n", users.user->nick, users.user->username);

    remove_user(&users, user);
}