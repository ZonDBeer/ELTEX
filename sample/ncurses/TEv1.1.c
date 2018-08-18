#include <stdio.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>

void sig_winch(int signo)
{
	struct winsize size;
	ioctl(fileno(stdout), TIOCGWINSZ, (char *) &size);
	resizeterm(size.ws_row, size.ws_col);
}

void _refresh(WINDOW *wnd, WINDOW *subwnd_text, WINDOW *subwnd_b1,
	WINDOW *subwnd_b2) {
	wrefresh(wnd);
	wrefresh(subwnd_text);
	wrefresh(subwnd_b1);
	wrefresh(subwnd_b2);
}

void _openf(WINDOW *subwnd_text, WINDOW *subwnd_b2, char *filename,
    char *text) {
    
    FILE *file;
    wclear(subwnd_text);
    if (strlen(filename) == 0) {
        int ch, i;
        i = 0;
        keypad(subwnd_b2, TRUE);
        wmove(subwnd_b2, 1, 0);
        wclrtoeol(subwnd_b2);
        mvwprintw(subwnd_b2, 1, 0, "open file:");
        wmove(subwnd_b2, 1, 10);
        while (((ch = wgetch(subwnd_b2)) != 10) && (i < 20)) {
            if (ch == KEY_BACKSPACE) {
                if (i == 0) continue;
                mvwaddch(subwnd_b2, 1, (10+i-1), ' ');
                wrefresh(subwnd_b2);
                wmove(subwnd_b2, 1, (10+i-1));
                i--;
                continue;
            }
            filename[i] = ch;
            wechochar(subwnd_b2, ch);
            ++i;
        }
        mvwprintw(subwnd_b2, 1, 0, "was open file: %s\n", filename);
    }
    file = fopen(filename, "r");
    fread(text, 1, 2048, file);
    fclose(file);
    wprintw(subwnd_text, text);
}

void next_position(int *x, int *y) {
	if(*x < 77) {
    	++(*x);
    } else {
    	if (*y < 22) {
    		++(*y);
    		*x = 0;
    	}
    }
}

void prev_position(int *x, int *y) {
	if(*x > 0) {
    	--(*x);
    } else {
    	if (*y > 0) {
    		--(*y);
    		*x = 77;
    	}
    }
}

void next_line(int *y) {
	if (*y < 22) {
		++(*y);
	}
}

void prev_line(int *y) {
	if (*y > 0) {
		--(*y);
	}
}

int main(int argc, char **argv) {
	WINDOW * wnd;
	WINDOW * subwnd_text;
	WINDOW * subwnd_b1;
	WINDOW * subwnd_b2;

    FILE *file;

	int x, y;

	char filename[20];
	char text[2048];

	initscr();
	signal(SIGWINCH, sig_winch);
	curs_set(FALSE);
	start_color();
	refresh();

	init_pair(1, COLOR_BLUE, COLOR_GREEN);
	init_pair(2, COLOR_BLACK, COLOR_BLUE);

	wnd = newwin(25, 80, 0, 0);
	wattron(wnd, COLOR_PAIR(1));
	box(wnd, '|', '-');

	subwnd_text = derwin(wnd, 23, 78, 1, 1);
	wbkgd(subwnd_text, COLOR_PAIR(2));

	subwnd_b1 = newwin(4, 80, 25, 0);
	wattron(subwnd_b1, COLOR_PAIR(1));
	box(subwnd_b1, '|', '-');

	subwnd_b2 = derwin(subwnd_b1, 2, 78, 1, 1);
	wbkgd(subwnd_b2, COLOR_PAIR(2));

	wprintw(subwnd_b2, "f1 - open file, f2 - save/close, f3 - exit\n");
	_refresh(wnd, subwnd_text, subwnd_b1, subwnd_b2);
	
	keypad(stdscr, true);
	noecho();

	x = 0;
    y = 0;
    bzero(filename, 20);
    bzero(text, 2048);

    if (argc > 1) {
        strncat(filename, argv[1], strlen(argv[1]));
        _openf(subwnd_text, subwnd_b2, filename, text);
        mvwprintw(subwnd_b2, 1, 0, "was open file: %s\n", argv[1]);
    }
    _refresh(wnd, subwnd_text, subwnd_b1, subwnd_b2);

	bool ex = false;
    while (!ex)
    {
        int ch = getch();

        switch (ch)
        {
        case KEY_UP:
            mvwaddch(subwnd_text, y, x, text[y*78+x]);
            prev_line(&y);
            mvwaddch(subwnd_text, y, x, text[y*78+x] | A_STANDOUT | A_BLINK);
            break;
        case KEY_DOWN:
            mvwaddch(subwnd_text, y, x, text[y*78+x]);
            next_line(&y);
            mvwaddch(subwnd_text, y, x, text[y*78+x] | A_STANDOUT | A_BLINK);
            break;    
        case KEY_RIGHT:
            mvwaddch(subwnd_text, y, x, text[y*78+x]);
            next_position(&x, &y);
            mvwaddch(subwnd_text, y, x, text[y*78+x] | A_STANDOUT | A_BLINK);
            break;
        case KEY_LEFT:
            mvwaddch(subwnd_text, y, x, text[y*78+x]);
            prev_position(&x, &y);
            mvwaddch(subwnd_text, y, x, text[y*78+x] | A_STANDOUT | A_BLINK);
            break;
        case KEY_F(1):
            bzero(filename, 20);
            _openf(subwnd_text, subwnd_b2, filename, text);
            break;
        case KEY_F(2):
            if (strlen(filename) > 0) {
                mvwprintw(subwnd_b2, 1, 0, "File was saved.\n");
                file = fopen(filename, "w");
                fwrite(text, 1, strlen(text), file);
                fclose(file);
            }
            break;
        case KEY_F(3):
            ex = true;
            break;
        default:
            mvwaddch(subwnd_text, y, x, ch);
            text[y*78+x] = ch;
            next_position(&x, &y);
            mvwaddch(subwnd_text, y, x, ch | A_STANDOUT | A_BLINK);
            break;
        }
        _refresh(wnd, subwnd_text, subwnd_b1, subwnd_b2);
    }
	endwin();
	return 0;
}