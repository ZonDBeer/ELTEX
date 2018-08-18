#include <stdio.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <dirent.h>

void sig_winch(int signo)
{
	struct winsize size;
	ioctl(fileno(stdout), TIOCGWINSZ, (char *) &size);
	resizeterm(size.ws_row, size.ws_col);
}

void _refresh(WINDOW *lwnd, WINDOW *lwndsub, WINDOW *rwnd,
	WINDOW *rwndsub) {
	wrefresh(lwnd);
	wrefresh(lwndsub);
	wrefresh(rwnd);
	wrefresh(rwndsub);
}

void _dirprint(DIR *leftd, DIR *rightd, WINDOW *lwndsub,
 WINDOW *rwndsub, int lpos, int rpos, int side,
  int *lcol, int *rcol) {
 	struct dirent *entry;
 	int counter;
 	wclear(lwndsub);
 	wclear(rwndsub);
 	rewinddir(leftd);
 	rewinddir(rightd);
 	counter = 0;
 	while((entry = readdir(leftd)) != NULL) {
 		if ((side == 0) && (lpos == counter)) {
 			wattron(lwndsub, A_STANDOUT);
 			wprintw(lwndsub, "%s\n", entry->d_name);
 			wattroff(lwndsub, A_STANDOUT);
 		} else {
 			wprintw(lwndsub, "%s\n", entry->d_name);
 		}
 		++counter;
 	}
 	*lcol = counter - 1;
 	counter = 0;
 	while((entry = readdir(rightd)) != NULL) {
 		if ((side == 1) && (rpos == counter)) {
 			wattron(rwndsub, A_STANDOUT);
 			wprintw(rwndsub, "%s\n", entry->d_name);
 			wattroff(rwndsub, A_STANDOUT);
 		} else {
 			wprintw(rwndsub, "%s\n", entry->d_name);
 		}
 		++counter;
 	}
 	*rcol = counter - 1;
}

int main() {
	WINDOW *lwnd, *lwndsub, *rwnd, *rwndsub;
	DIR *leftd, *rightd;
	int lpos, rpos, side, lcol, rcol;
	int counter;
    struct dirent *entry;
	bool exit = false;
	char lpath[1024], rpath[1024];
	bzero(lpath, 1024);
	bzero(rpath, 1024);
	initscr();
	signal(SIGWINCH, sig_winch);
	curs_set(FALSE);
	start_color();
	refresh();

	init_pair(1, COLOR_BLUE, COLOR_GREEN);
	init_pair(2, COLOR_BLACK, COLOR_BLUE);

	lwnd = newwin(25, 40, 0, 0);
	wattron(lwnd, COLOR_PAIR(1));
	box(lwnd, '|', '~');

	lwndsub = derwin(lwnd, 23, 38, 1, 1);
	wbkgd(lwndsub, COLOR_PAIR(2));

	rwnd = newwin(25, 40, 0, 40);
	wattron(rwnd, COLOR_PAIR(1));
	box(rwnd, '|', '~');

	rwndsub = derwin(rwnd, 23, 38, 1, 1);
	wbkgd(rwndsub, COLOR_PAIR(2));

	lpos = rpos = side = 0;

	leftd = opendir(".");
	strncat(lpath, ".", 1);
	rightd = opendir(".");
	strncat(rpath, ".", 1);

	_dirprint(leftd, rightd, lwndsub, rwndsub,
	 lpos, rpos, side, &lcol, &rcol);

	keypad(stdscr, true);
	noecho();

	_refresh(lwnd, lwndsub, rwnd, rwndsub);
	while (!exit)
    {
        int ch = getch();

        switch (ch)
        {
        case KEY_UP:
        	if (side == 0) {
        		if (lpos > 0) {
        			--lpos;
        		}
        	} else {
        		if (rpos > 0) {
        			--rpos;
        		}
        	}
            break;
        case KEY_DOWN:
        	if (side == 0) {
        		if (lpos < lcol) {
        			++lpos;
        		}
        	} else {
        		if (rpos < rcol) {
        			++rpos;
        		}
        	}
            break;
        case '\t':
        	if (side == 0) {
        		side = 1;
        	} else {
        		side = 0;
        	}
        	break;
        case '\n':
        	counter = 0;
        	rewinddir(leftd);
        	rewinddir(rightd);
        	if (side == 0) {
        		while((entry = readdir(leftd)) != NULL) {
			 		if (counter == lpos)
			 			break;
 					++counter;
 				}
 				strncat(lpath, "/", 1);
 				strncat(lpath, entry->d_name, strlen(entry->d_name));
 				//printw(lpath);
 				closedir(leftd);
 				leftd = opendir(lpath);
 				lpos = 0;
        	} else {
        		while((entry = readdir(rightd)) != NULL) {
			 		if (counter == rpos)
			 			break;
 					++counter;
 				}
 				strncat(rpath, "/", 1);
 				strncat(rpath, entry->d_name, strlen(entry->d_name));
 				//printw(rpath);
 				closedir(rightd);
 				rightd = opendir(rpath);
 				rpos = 0;
        	}
        	break;
        default:
            break;
        }
        _dirprint(leftd, rightd, lwndsub, rwndsub,
	     lpos, rpos, side, &lcol, &rcol);
        _refresh(lwnd, lwndsub, rwnd, rwndsub);
    }

	endwin();
	refresh();
	getch();
	return 0;
}