#include <nps.h>
#include <ncurses.h>
#include <string.h>

Cmd cmd;

const static int mc = 80;
const static int mr = 25;

void cmd_put_char(char c) {
    cmd.cmd[cmd.write] = c;
    if (cmd.write < CMD_SIZE - 1)
        cmd.write++;
    nps_view();
}

void cmd_pop_char() {
    if (cmd.write > 0)
        cmd.write--;
    cmd.cmd[cmd.write] = 0;
    nps_view();
}

void cmd_exec() {
    memset(&cmd, 0, sizeof(cmd));
    nps_view();
}

void view_init() {
    memset(&cmd, 0, sizeof(cmd));
    /* 初始化 ncurses */
    initscr();
    cbreak();
    noecho();
    curs_set(0); /* 隐藏光标 */
    refresh();
    /* 颜色板 */
    start_color();
    /* header color */
    init_pair(1, COLOR_BLACK, COLOR_WHITE);
    /* status color */
    init_pair(2, COLOR_YELLOW, COLOR_BLACK);
}

static void print_border(int y, int x, Bd_Type bt) {
    move(y, x);
    int c;
    for (c = 0; c < mc; c++) {
        if (c == 0) {
            switch (bt) {
                case UP:
                    addch(ACS_ULCORNER);
                    break;
                case DOWN:
                    addch(ACS_LLCORNER);
                    break;
                case NORMAL:
                    addch(ACS_LTEE);
            }
            continue;
        }
        if (c == mc - 1) {
            switch (bt) {
                case UP:
                    addch(ACS_URCORNER);
                break;
                case DOWN:
                    addch(ACS_LRCORNER);
                break;
                case NORMAL:
                    addch(ACS_RTEE);
            }
            continue;
        }
        addch(ACS_HLINE);
    }
}

static void print_title(int y, int x, const char *title) {
    attron(COLOR_PAIR(1) | A_BOLD | A_STANDOUT);
    mvprintw(y, x, title);
    int pad = mc - strlen(title) - 3;
    int i;
    for (i = 0; i < pad; i++) {
        addch(' ');
    }
    attroff(COLOR_PAIR(1) | A_BOLD | A_STANDOUT);
    attroff(COLOR_PAIR(1) | A_BOLD | A_STANDOUT);
}

void nps_set_result(const char *msg) {
    strcpy(cmd.rst, msg);
}

void nps_view() {
    clear();
    /* Service Table */
    int r = 0;
    print_border(r++, 0, UP);
    move(r, 0);
    int c;
    for (c = 0; c < mc; c++) {
        if (c == 0 || c == mc - 1) {
            addch(ACS_VLINE);
            continue;
        }
        addch(' ');
    }
    print_title(r++, 2, "Service Table");
    print_border(r++, 0, NORMAL);
    move(r, 0);
    addch(ACS_VLINE);
    mvprintw(r, 2, "%10s%10s%10s%10s%17s%10s%10s", "ServID", "SockID", "Protocol", "Port", "Status", "Buffer", "Clients");
    move(r++, mc - 1);
    addch(ACS_VLINE);
    print_border(r++, 0, NORMAL);
    Dev_Service *st = service_table();
    int i;
    for (i = 0; i < 3; i++) {
        Dev_Service *sv = st + i;
        if (sv->protocol == 0) continue;
        move(r, 0);
        addch(ACS_VLINE);
        mvprintw(r, 2, "%10d%10d%10s%10d%17s%10d%10d",
            i, sv->sockid, service_protocol_str(sv), sv->port, "",
            sv->ibuf.size, sv->clients.size);
        move(r, mc - 1);
        addch(ACS_VLINE);
        attron(COLOR_PAIR(2) | A_BOLD);
        mvprintw(r, 42, "%17s", service_status_str(sv));
        attroff(COLOR_PAIR(2) | A_BOLD);
        r++;
    }
    print_border(r++, 0, DOWN);
    print_border(r++, 0, UP);
    move(r, 0);
    for (c = 0; c < mc; c++) {
        if (c == 0 || c == mc - 1) {
            addch(ACS_VLINE);
            continue;
        }
        addch(' ');
    }
    print_title(r++, 2, "Command Control");
    print_border(r++, 0, NORMAL);
    move(r, 0);
    for (c = 0; c < mc; c++) {
        if (c == 0 || c == mc - 1) {
            addch(ACS_VLINE);
            continue;
        }
        addch(' ');
    }
    mvprintw(r, 1, "CMD >");
    mvprintw(r, 10, "%s", cmd.cmd);
    r++;
    mvaddch(r, 0, ACS_VLINE);
    mvaddch(r, mc - 1, ACS_VLINE);
    r++;
    mvaddch(r, 0, ACS_VLINE);
    mvprintw(r, 1, cmd.rst);
    mvaddch(r, mc - 1, ACS_VLINE);
    r++;
    print_border(r, 0, DOWN);
    refresh();
}