#include <stdio.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>

void _sig_winch(int signo) {
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

void _dirprint(char *path, char *name, WINDOW *wndsub,
	int pos, int side, int *col, int *allow) {
	int num;
	struct dirent **namelist;
 	struct stat sb;
 	//char tmp[100];
 	*allow = 1;

 	wclear(wndsub);

 	bzero(name, 100);
 	//bzero(tmp, 100);

 	if (chdir(path)) {
        printf("error(chdir):%s", path);
        exit(EXIT_FAILURE);
    }

 	num = scandir(path, &namelist, NULL, NULL);
 	if (num == -1) {
 		perror("scandir error");
 		exit(EXIT_FAILURE);
 	}
 	*col = num - 1;
 	for(int i = 0; i < num; ++i) {
 		if (pos == i) {
 			wattron(wndsub, A_STANDOUT);
 			strncat(name, namelist[i]->d_name, strlen(namelist[i]->d_name));

 			// bzero(tmp, 100);
 			// strncat(tmp, path, strlen(path));
 			// strncat(tmp, namelist[i]->d_name, strlen(namelist[i]->d_name));

 			// if (stat(namelist[i]->d_name, &sb) == -1) {
    //            perror("stat error");
    //            exit(EXIT_FAILURE);
    //     	}
    //     	switch (sb.st_mode & S_IFMT) {
    //         case S_IFDIR:  wprintw(wndsub, "DIR"); *allow = 1; 			break;
    //         case S_IFREG:  wprintw(wndsub, "RFL"); *allow = 0;  		break;
    //         default:       wprintw(wndsub, "UNK");	*allow = 0;			break;
    //         }
            wprintw(wndsub, "\t%s\n", namelist[i]->d_name);
            wattroff(wndsub, A_STANDOUT);
        } else {

    		//bzero(tmp, 100);
 			// strncat(tmp, path, strlen(path));
 			// strncat(tmp, namelist[i]->d_name, strlen(namelist[i]->d_name));

        	// if (stat(namelist[i]->d_name, &sb) == -1) {
         //       perror("stat error");
         //       exit(EXIT_FAILURE);
        	// }
        	// switch (sb.st_mode & S_IFMT) {
         //    case S_IFDIR:  wprintw(wndsub, "DIR");		break;
         //    case S_IFREG:  wprintw(wndsub, "RFL");		break;
         //    default:       wprintw(wndsub, "UNK");		break;
         //    }
            wprintw(wndsub, "\t%s\n", namelist[i]->d_name);
        }
 		free(namelist[num]);
 	}
 	free(namelist);
}

int main() {
	WINDOW *lwnd, *lwndsub, *rwnd, *rwndsub;

	int lpos, rpos, side, lcol, rcol, allow;

	bool exit = false;
	
	char lpath[4096], rpath[4096];
	bzero(lpath, 4096);
	bzero(rpath, 4096);

	realpath(".", lpath);
	realpath(".", rpath);

	char lname[100], rname[100];
	bzero(lname, 100);
	bzero(rname, 100);

	initscr();
	signal(SIGWINCH, _sig_winch);
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

	_dirprint(lpath, lname, lwndsub, lpos, side, &lcol, &allow);
	_dirprint(rpath, rname, rwndsub, rpos, side, &rcol, &allow);
	_refresh(lwnd, lwndsub, rwnd, rwndsub);

	keypad(stdscr, true);
	noecho();

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
        	if ((!side) && allow) {
        		strncat(lpath, "/", 1);
        		strncat(lpath, lname, strlen(lname));
        		if (chdir(lpath)) {
        			printf("error(chdir):%s", lpath);
        			return(-1);
        		}
        		realpath(".", lpath);
        		lpos = 0;
        	} else if (side && allow) {
        		strncat(rpath, "/", 1);
        		strncat(rpath, rname, strlen(rname));
        		if (chdir(rpath)) {
        			printf("error(chdir):%s", rpath);
        			return(-1);
        		}
        		realpath(".", rpath);
        		rpos = 0;
        	}
        	break;
        case 'q':
        	exit = 1;
        	break;
        default:
            break;
        }
        if (side) {
        	_dirprint(lpath, lname, lwndsub, lpos, side, &lcol, &allow);
			_dirprint(rpath, rname, rwndsub, rpos, side, &rcol, &allow);
        } else {
        	_dirprint(rpath, rname, rwndsub, rpos, side, &rcol, &allow);
	        _dirprint(lpath, lname, lwndsub, lpos, side, &lcol, &allow);
		}
		_refresh(lwnd, lwndsub, rwnd, rwndsub);
    }
	endwin();
	refresh();
	return 0;
}