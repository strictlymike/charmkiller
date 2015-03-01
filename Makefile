TARGET = killcharms.exe

CC = cl.exe
CFLAGS = $(CFLAGS) /Zi
RM = DEL /Q
CLEANFILES = $(TARGET) *.exp *.obj *.pdb *.ilk

all: $(TARGET)

.cpp.exe:
	$(CC) $** $(LIBS) $(CFLAGS)

.c.exe:
	$(CC) $** $(LIBS) $(CFLAGS)

clean:
	$(RM) $(CLEANFILES) > NUL 2>&1
