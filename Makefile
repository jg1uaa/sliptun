TARGET = sliptun

$(TARGET): $(TARGET).c
	$(CC) -Wall -O2 -pthread $< -o $@

clean:
	rm -f $(TARGET)
