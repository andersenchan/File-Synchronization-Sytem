#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <libgen.h>
#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ftree.h"
#include "hash.h"

#define MAX_BACKLOG 5
#define MAX_CONNECTIONS 25
#define BUF_SIZE 128

struct sockstate {
    int sock_fd;
    int state;
    int send_error;
    struct request *req;
    FILE *fp;
    char full_path[MAXDATA];
};

char *extract_name(const char *pathname) {
    int length = strlen(pathname);
    int i = length - 1;
    if (pathname[i] == '/') {
	i--;
    }
    while (i > 0 && pathname[i] != '/') {
	i--;
    }
    if (i > 0 && pathname[i] == '/') {
	i++;
    }
    char *name = malloc(sizeof(char)*(length - i + 1));
    int j=0;
    while (i < length){
        name[j] = pathname[i];
	i++;
	j++;
    }
   name[j] = '\0';

   return name;
}

/* Accept a connection. Note that a new file descriptor is created for
 * communication with the client. The initial socket descriptor is used
 * to accept connections, but the new socket is used to communicate.
 * Return the new client's file descriptor or -1 on error.
 */
int accept_connection(int fd, struct sockstate *sock_fds) {
    int user_index = 0;
    while (user_index < MAX_CONNECTIONS && (sock_fds[user_index]).sock_fd != -1) {
        user_index++;
    }

    int client_fd = accept(fd, NULL, NULL);
    if (client_fd < 0) {
        perror("server: accept");
        close(fd);
        return -1;
    }

    if (user_index == MAX_CONNECTIONS) {
        fprintf(stderr, "server: max concurrent connections\n");
        close(client_fd);
        return -1;
    }

    // Initialize the server's request struct
    // This needs to be done only once, since we will just replace it when reading new structs
    (sock_fds[user_index]).sock_fd = client_fd;
    // First thing we expect to recieve from the client is the type
    (sock_fds[user_index]).state = AWAITING_TYPE; 
    (sock_fds[user_index]).req = malloc(sizeof(struct request));

    return client_fd;
}

/* Read a request from client_index and 
 * //Return the fd if it has been closed or 0 otherwise.
 *
 * If the file is the same, return OK, otherwise, return SENDFILE
 * If an error is encountered, return ERROR
 */
int check_file(int client_index, struct sockstate *sock_fds) {

    struct request *buf = (sock_fds[client_index]).req;

    // Open the directory
    DIR *dirp = opendir("./");
    if (dirp == NULL) {
        perror("opendir");
        return ERROR;
    }
	
	
    // See if the file exists in the directory (if there is a file with the same name)
    struct dirent *direntp = readdir(dirp);
    int samename = 0;
    while (direntp != NULL) {
        if (strcmp(direntp->d_name, extract_name(buf->path)) == 0) {
            samename = 1;
        }
	   direntp = readdir(dirp);
    }

    // Close the directory
    if (closedir(dirp) == -1) {
        perror("closedir");
        return ERROR;
    }
	
	 if (samename == 0) {
	 	
	 	// If the directory doest exist, mkdir and return OK
		if (buf->type == REGDIR){
			mkdir((sock_fds[client_index]).full_path, buf->mode);
			return OK;
			
		// If the file doesnt exist, return SENDFILE
		} else if (buf->type == REGFILE){
			return SENDFILE;
		} else {
			return ERROR;     
		}
    }

    
	//do we need to add the server path to the path we get? add ./ ?
    
    struct stat file_info; // in the destination folder
    if (lstat(buf->path, &file_info) == -1) {
        perror("lstat");
        return ERROR;
    }

    // If request is a directory
    if (buf->type == REGDIR) {
    	if(S_ISREG(file_info.st_mode)) {
            // Mismatch: Change permissions and return ERROR
            if (chmod(buf->path, buf->mode) == -1) {
                perror("chmod");
                return ERROR;
            }
    	    return ERROR;
    	} else {

    		// Match: Simply change the permissions, and return OK
		 	if (chmod(buf->path, buf->mode) == -1) {
		 		perror("chmod");
		 		return ERROR;
		 	}   
      }        

    // If request is a regular file
    } else if (buf->type == REGFILE) {
    	if(S_ISDIR(file_info.st_mode)) {

         // Mismatch: Change permissions and return ERROR
		 	if (chmod(buf->path, buf->mode) == -1) {
		 		perror("chmod");
		 		return ERROR;
		 	}
    	    return ERROR;
    	    
    	} else {

    		// Compare file sizes
		    if (file_info.st_size != buf->size) {
		        return SENDFILE;
		    }

            //is this reading the file from server as it should, or is it client?

            // Check the file hashes
            FILE *fp = fopen(buf->path, "rb");
            if (fp == NULL) {
                perror("fopen");
                return ERROR;
            }
            char *fphash = hash(fp);
            if (!check_hash(fphash, buf->hash)) {
            	return SENDFILE;
            } 
        }
    } else if (buf->type == TRANSFILE) {
		// We will never get here; this function isn't called in this case.
    }
    /*
    if (num_read == 0 || write(fd, buf, strlen(buf)) != strlen(buf)) {
        sock_fds[client_index] = -1;
        return fd;
    }
    */
    return OK;
}

/* Read type from client
*  Return 0 on successs, fd when fd is closed
*/
int read_type(int client_index, struct sockstate *sock_fds) {
	uint32_t type;
	int fd = (sock_fds[client_index]).sock_fd;

	// Should only read 1 int
	int num_read = read(fd, &type, sizeof(uint32_t));
	if (num_read == 0) {
		printf("Error reading type from client %d\n", fd);
        (sock_fds[client_index]).send_error = 1;
		return 0;
	}
		
	(sock_fds[client_index]).req->type = (int) ntohl(type);
	printf("Read type %d from client\n",(sock_fds[client_index]).req->type);
	
	if((sock_fds[client_index]).req->type == DONE){
		if(close(fd) == -1) {
			perror("close");
		}
      printf("Client %d disconnected\n", fd);
      (sock_fds[client_index]).sock_fd = -1;
      return fd;
	}
	
	// Set next state
	(sock_fds[client_index]).state = AWAITING_PATH;
	//printf("STATE it is: %d\nState it should be: %d\n", (sock_fds[client_index]).state, AWAITING_PATH);
	
	return 0;
}

/* Read path from client
*  Return 0 on successs, 1 on failure
*/
int read_path(int client_index, struct sockstate *sock_fds) {
	int fd = (sock_fds[client_index]).sock_fd;

	// Set next state
	(sock_fds[client_index]).state = AWAITING_SIZE;

	int num_read = read(fd, &((sock_fds[client_index]).req->path), MAXPATH);
	if (num_read <= 0) {
		printf("Error reading path from client %d\n", fd);
		return 1;
	}
        
   printf("Read path %s from client. \n", (sock_fds[client_index]).req->path );
    
	return 0;
}

/* Read size from client
*  Return 0 on successs, 1 on failure
*/
int read_size(int client_index, struct sockstate *sock_fds) {
	uint32_t size;
	int fd = (sock_fds[client_index]).sock_fd;


	// Set next state
	(sock_fds[client_index]).state = AWAITING_PERM;

	// Should only read 1 int
	int num_read = read(fd, &size, sizeof(uint32_t));
	if (num_read <= 0) {
		printf("Error reading size from client %d\n", fd);
		return 1;
	}

	(sock_fds[client_index]).req->size = (int) ntohl(size);
   printf("Read size %d from client. \n", (sock_fds[client_index]).req->size);
   
	return 0;
}

/* Read permissions from client
*  Return 0 on successs, 1 on failure
*/
int read_perm(int client_index, struct sockstate *sock_fds) {
	 uint32_t perm;
    int fd = (sock_fds[client_index]).sock_fd;

    // Set next state
    (sock_fds[client_index]).state = AWAITING_HASH;

    int num_read = read(fd, &perm, sizeof(mode_t));
    if (num_read <= 0) {
        printf("Error reading mode from client %d\n", fd);
        return 1;
    }

	 (sock_fds[client_index]).req->mode = (int) ntohl(perm);
	 printf("Read mode %d from client. \n", (sock_fds[client_index]).req->mode);
	 
    return 0;
}

/* Read hash from client
*  Return 0 on successs, 1 on failure
*/
int read_hash(int client_index, struct sockstate *sock_fds) {
	int fd = (sock_fds[client_index]).sock_fd;

    // Set next state
    (sock_fds[client_index]).state = CHECKING_FILE;

    int num_read = read(fd, &((sock_fds[client_index]).req->hash), BLOCKSIZE);
    if (num_read <= 0) {
        printf("Error reading hash from client %d\n", fd);
        return 1;
    }
    printf("Read hash %s from client. \n", (sock_fds[client_index]).req->hash );
    

    return 0;
}

/* Opens the path that the client sent us, and read data from the client,
 * and copy the client data directly into it, MAXDATA bits at a time 
 * 
 * Return 0 if successful, return 1 otherwise
 */
int copy_file(int client_index, struct sockstate *sock_fds, FILE *fp){

	char data[MAXDATA];
    int fd = (sock_fds[client_index]).sock_fd;

    int numread = read(fd, data, MAXDATA);
	 //printf("NUMREAD: %d\n", numread);
    if (numread < 0){
        printf("error in server: copy_file");
		  int temp = ERROR;

        // Tell client that an error occured during the copy
        if(write(fd, &temp, sizeof(int)) == -1) {
            perror("server: copy_file, writing ERROR");
            return 1;
        }
        /*
        while(write(fd, ERROR, sizeof(int)) == -1) {
            perror("server: copy_file, writing ERROR");
        }*/

    // If the read was successful
    } else {
    	//printf("%d\n", numread);
       if(fwrite(data, 1, numread, fp) < numread) {
            perror("server: copy_file, writing ERROR");
            return 1;
        }
    }

    // If this is the last chunk of data (i.e. the file has been copied completely),
    if (numread < MAXDATA) { 

    	// Change the permissions of the file (to what the source file's permissions were?)
        if (chmod((sock_fds[client_index]).full_path, (sock_fds[client_index]).req->mode) == -1) {
            perror("chmod");
            return ERROR;
        }

	    // Tell client that we are done copying by sending an OK
	    int temp = OK;
	    if(write(fd, &temp, sizeof(int)) == -1) {
	        perror("server: copy_file, writing OK");
	        return 1;
	    }

	    // Close fd since we're done with it
	    if (close(fd) == -1) {
	    	perror("server: copy_file close client fd");
	    	return 1;
	    }

	    (sock_fds[client_index]).sock_fd = -1;

        // Close the file
        if (fclose(fp) == -1) {
            perror("server: fclose");
            return 1;
        }
	}

    // No need to change the state, either server is still AWAITING_DATA,
    // or we are dealing with a child client, which will close

    return 0;
}

void rcopy_server(unsigned short port){

    struct sockstate sock_fds[MAX_CONNECTIONS];
    for (int index = 0; index < MAX_CONNECTIONS; index++) {
        (sock_fds[index]).sock_fd = -1;
        (sock_fds[index]).req = NULL;
	    (sock_fds[index]).send_error = 0;
	    (sock_fds[index]).fp = NULL;
    }

    // Create the socket FD.
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("server: socket");
        exit(1);
    }

    // Set information about the port (and IP) we want to be connected to.
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = INADDR_ANY;

    // This should always be zero. On some systems, it won't error if you
    // forget, but on others, you'll get mysterious errors. So zero it.
    memset(&server.sin_zero, 0, 8);

    // Bind the selected port to the socket.
    if (bind(sock_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("server: bind");
        close(sock_fd);
        exit(1);
    }

    // Announce willingness to accept connections on this socket.
    if (listen(sock_fd, MAX_BACKLOG) < 0) {
        perror("server: listen");
        close(sock_fd);
        exit(1);
    }

    // The client accept - message accept loop. First, we prepare to listen to multiple
    // file descriptors by initializing a set of file descriptors.
    int max_fd = sock_fd;
    fd_set all_fds, listen_fds;
    FD_ZERO(&all_fds);
    FD_SET(sock_fd, &all_fds);

	// Wait up to five seconds before select times out.
	struct timeval tv;
   tv.tv_sec = 5;
   tv.tv_usec = 0;
   int readt_return = 0;
           
	printf("Server done setup.\n");
	
    while (1) {
        // select updates the fd_set it receives, so we always use a copy and retain the original.
        listen_fds = all_fds;
        int nready = select(max_fd + 1, &listen_fds, NULL, NULL, &tv);
        if (nready == -1) {
            perror("server: select");
            exit(1);
        }

        // Is it the original socket? Create a new connection ...
        if (FD_ISSET(sock_fd, &listen_fds)) {
            int client_fd = accept_connection(sock_fd, sock_fds);
            if (client_fd > max_fd) {
                max_fd = client_fd;
            }
            FD_SET(client_fd, &all_fds);
            printf("Accepted connection. \n");
        }

        // Next, check the clients.
        // NOTE: We could do some tricks with nready to terminate this loop early.
        for (int index = 0; index < MAX_CONNECTIONS; index++) {
            if (sock_fds[index].sock_fd > -1 && FD_ISSET(sock_fds[index].sock_fd, &listen_fds)) {
                // Note: never reduces max_fd
                /*int client_closed = read_from(index, sock_fds);
                if (client_closed > 0) {
                    FD_CLR(client_closed, &all_fds);
                    printf("Client %d disconnected\n", client_closed);
                } else {
                    printf("Echoing message from client %d\n", sock_fds[index]);
                }*/
                
                switch((sock_fds[index]).state){
                    case AWAITING_TYPE: 
                        readt_return = read_type(index, sock_fds); 
                        if(readt_return > 0){
                        	// How do we let the client know, since its not listening?
                        	// Maybe have a failed flag, read the others as normal, and then
                        	// when it's listening, BAM!, we send it ERROR, and if sending
                        	// ERROR fails we close that SOB.
                            FD_CLR(readt_return, &all_fds);
                        }
                        break;
                    case AWAITING_PATH: 
                        if(read_path(index, sock_fds) == 1){
                        	// How do we let the client know, since its not listening?
									(sock_fds[index]).send_error = 1;
                        }
                        break;
                    case AWAITING_SIZE: 
                        if(read_size(index, sock_fds) == 1){
                        	// How do we let the client know, since its not listening?
									(sock_fds[index]).send_error = 1;
                        }
                        break;
                    case AWAITING_PERM: 
                        if(read_perm(index, sock_fds) == 1){
                        	// How do we let the client know, since its not listening?
									(sock_fds[index]).send_error = 1;
                        }
                        break;
                    case AWAITING_HASH: 
                        if(read_hash(index, sock_fds) == 1){
                        	// How do we let the client know, since its not listening?
									(sock_fds[index]).send_error = 1;
                        }
                        
                            strcpy((sock_fds[index]).full_path, ".");
                            strcat((sock_fds[index]).full_path, (sock_fds[index]).req->path);
			
						if ((sock_fds[index]).send_error == 1) {
			   				uint32_t temp = htonl(ERROR); // TODO: instantiate outside of loops.
                        if(write((sock_fds[index]).sock_fd, &temp, sizeof(uint32_t)) == -1) {
                            perror("server: sending error");
                                //exit(1);
			    			}								
			    				//Set next state, or close?
						}

                        // Change the next state depending on the type
                        else if ((sock_fds[index]).req->type == TRANSFILE){
                            // We dont need to send to the client in this case
			                 //Open the file for writing, once
                           (sock_fds[index]).fp = fopen((sock_fds[index]).full_path, "wb");

									(sock_fds[index]).state = AWAITING_DATA;             
        
                        } else if (sock_fds[index].req->type == REGDIR || sock_fds[index].req->type == REGFILE){
                        	uint32_t response = htonl(check_file(index, sock_fds)); // still need to check for dir and file
                        	
                    			// Send a response to the client
                    			printf("Sending %d to the client.\n", ntohl(response));
                           if(write((sock_fds[index]).sock_fd, &response, sizeof(uint32_t)) == -1) {
                                perror("client: write path");
                                exit(1);
                           }
                        	(sock_fds[index]).state = AWAITING_TYPE;
                        }
                        break;
                    case AWAITING_DATA: 
                        copy_file(index, sock_fds, (sock_fds[index]).fp);
                        break;
                    default: break; //send error since no state?
                }
        	}
    	}
    }
    // Should never get here
}

int rcopy(char *src_n_full, int sock_fd, struct sockaddr_in *sp, char * relative_path){
	char src_n[MAXPATH];
	strcpy(src_n, relative_path);
	strcat(src_n, "/");
    strcat(src_n, extract_name(src_n_full));
	printf("Current file descriptor: %d\n",sock_fd);
    struct sockaddr_in server = *sp;
    
    /* Initialize the struct to be transfered */
    
    struct request *s_request = malloc(sizeof(struct request));
    strncpy(s_request->path, src_n, MAXPATH);


    struct stat s_st;
    //char*path = getcwd();
    if ((lstat(src_n_full, &s_st)) == -1){ 
        perror("lstat");
        exit(-1);
    }

    s_request->mode = s_st.st_mode;
    //s_request->hash = NULL;
    //s_request->type = NULL;
    if (S_ISREG(s_st.st_mode)){
      FILE *fp = fopen(src_n_full, "rb");
      if(fp == NULL){
			perror("fopen");
			exit(1);      
      }
		// Compute the hash and copy it into the request.
		char *hashed = hash(fp);
		int i = 0;
		while (i < BLOCKSIZE) {
	   	(s_request->hash)[i] = hashed[i];
	   	i++;
		}	
    	s_request->type = REGFILE;
    	s_request->size = s_st.st_size;
    } else if (S_ISDIR(s_st.st_mode)){
        s_request->type = REGDIR;
    	s_request->size = 0;
    }
    
    // Send the struct to the server
    
    printf("Sending request to server.\n");
	
    uint32_t type_to_send = htonl(s_request->type);
    printf("Sending type: %d to server\n", s_request->type);
    if(write(sock_fd, &type_to_send, sizeof(uint32_t)) == -1) {
        perror("client: write type");
        exit(1);
    }
    printf("Sending path: %s to server\n", s_request->path);
    if(write(sock_fd, s_request->path, MAXPATH) == -1) {
        perror("client: write path");
        exit(1);
    }
    printf("Sending size: %d to server\n", s_request->size);
    uint32_t size_to_send = htonl(s_request->size);
    if(write(sock_fd, &size_to_send, sizeof(uint32_t)) == -1) {
        perror("client: write size");
        exit(1);
    }
    printf("Sending mode %d to server\n", s_request->mode);
    uint32_t mode_to_send = htonl(s_request->mode);
    if(write(sock_fd, &mode_to_send, sizeof(uint32_t)) == -1) {
        perror("client: write mode");
            exit(1);
    }
    printf("Sending hash: %s to server\n", s_request->hash);
    if(write(sock_fd, s_request->hash, BLOCKSIZE) == -1) {
        perror("client: write hash");
        exit(1);
    }
    
    // Wait for a response from server
    uint32_t buf_temp;
    if(read(sock_fd, &buf_temp, sizeof(uint32_t)) <= 0) {
        perror("client: read");
        exit(1);
    }
    int buf = ntohl(buf_temp);
    // If server sent SENDFILE, fork and transfer data
    if (buf == SENDFILE){ 
        int r = fork();
        
        if (r < 0) {
				perror("fork");
				exit(1);        
        } else if (r == 0){ //Child process

            // Create the socket FD.
            int sock_fd_child = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd_child < 0) {
                perror("client: socket");
                exit(1);
            }

            // Connect to the server.
            if (connect(sock_fd_child, (struct sockaddr *)&server, sizeof(server)) == -1) {
                perror("client: connect");
                close(sock_fd_child);
                exit(1);
            }
            
            // Send the struct to the server
            s_request->type = TRANSFILE;
            printf("Sending child struct to server\n");

    			uint32_t type_to_send_child = htonl(s_request->type);
    			printf("Sending type: %d to server\n", type_to_send_child);
    			if(write(sock_fd_child, &(type_to_send_child), sizeof(uint32_t)) == -1) {
        			perror("client: write type");
        			exit(1);
        		}
            printf("Sending path: %s to server\n", s_request->path);
            if(write(sock_fd_child, s_request->path, MAXPATH) == -1) {
                perror("client: write path");
                exit(1);
            }
            printf("Sending size: %d to server\n", s_request->size);
            uint32_t size_to_send = htonl(s_request->size);
    			if(write(sock_fd_child, &size_to_send, sizeof(uint32_t)) == -1) {
        			perror("client: write size");
        			exit(1);
    			}
            printf("Sending mode %d to server\n", s_request->mode);
    			uint32_t mode_to_send = htonl(s_request->mode);
    			if(write(sock_fd_child, &mode_to_send, sizeof(uint32_t)) == -1) {
        			perror("client: write mode");
            	exit(1);
    			}
    			printf("Sending hash: %s to server\n", s_request->hash);
            if(write(sock_fd_child, s_request->hash, BLOCKSIZE) == -1) {
                perror("client: write hash");
                exit(1);
            }

            // Open the source file
            FILE* srcf = fopen(src_n_full, "rb"); // reading (binary)
            if(srcf == NULL){
                perror("fopen(src_n)");
                exit(1);
            }
            
            // Transmit MAXDATA bits at a time
            char data[MAXDATA];
				int data_len;
				int nw = 69;
            while ((data_len = fread(data, 1, MAXDATA, srcf)) != 0){
            	//printf("datalen: %d\ndata: %s\n", data_len, data);
                if((nw = write(sock_fd_child, data, data_len)) == -1){
                    perror("fwrite");
                    exit(1);
                }
                //printf("%d\n", nw);
            } 
            fclose(srcf);

            // Wait for a response from server
            if(read(sock_fd_child, &buf, sizeof(buf)) <= 0) {
                perror("client: read");
                exit(1);
            }
            
            // Handle the response form the server
            if (buf != OK){ 
                if (buf == ERROR){
                    printf("Error (on the server side) copying the file %s", src_n);
                } else {
                    printf("Error (on the client side) copying the file %s", src_n);    
                }
                close(sock_fd_child);
                exit(1);
            } // If the transfer was a success
                close(sock_fd_child);
                exit(0);
        }


    } else if (buf != OK){ 
        close(sock_fd);
        return -1;
    }

    /* Copying the subdirs of src */
	
	//printf("Copying the subdirs. %d\n", S_ISDIR(s_st.st_mode));
    if (S_ISDIR(s_st.st_mode)){
        struct dirent *dp;
        DIR *dirp = opendir(src_n_full);
        if(dirp == NULL) {
            perror("opendir");
            exit(-1);
        }
        dp = readdir(dirp);
        
        while (dp != NULL){
            if(((*dp).d_name)[0] != '.'){
            	 
            	 char path[MAXPATH];
            	 strcpy(path, src_n_full);
            	 strcat(path, "/");
            	 strcat(path, dp->d_name);
					printf("Recursing on %s", path);
                rcopy(path, sock_fd, &server, src_n);
            }
            dp = readdir(dirp);
        }
        closedir(dirp);
        printf("Done Copying subdirs of %s.\n", src_n_full);
    }

    return 0;

}
int rcopy_client(char *source, char *host, unsigned short port){
	
    // Create the socket FD.
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("client: socket");
        exit(1);
    }

    // Set the IP and port of the server to connect to.
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) < 1) {
        perror("client: inet_pton");
        close(sock_fd);
        exit(1);
    }

    // Connect to the server.
    if (connect(sock_fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("client: connect");
        close(sock_fd);
        exit(1);
    }
    
    printf("Connected to server.\n");

    // Copy the source to the server
    int result = rcopy(source, sock_fd, &server, "");
    
    // Let the socket know that we are closing the socket
    printf("Sending DONE type to server\n");
    uint32_t type_to_send = htonl(DONE);
    printf("Sending type: %d to server\n", ntohl(type_to_send));
    if(write(sock_fd, &(type_to_send), sizeof(uint32_t)) == -1) {
       perror("client: write type");
        exit(1);
    }    
    
    if(close(sock_fd) == -1) {
		perror("close");
	}

	// Wait for all the children
    int status;
    if(wait(&status) == -1){
        perror("wait");
    }

    return result;
}
