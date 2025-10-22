activate application "iTerm"
tell application "iTerm"
    tell current tab of current window
        delay 1
        set cmd to "docker mysecret rm GH_TOKEN"
        tell application "System Events"
            keystroke cmd
            keystroke return
        end tell
        delay 1
        set cmd to "docker rm -f demo"
        tell application "System Events"
            keystroke cmd
            keystroke return
        end tell
        delay 1
        set cmd to "clear"
        tell application "System Events"
            keystroke cmd
            keystroke return
        end tell
        delay 2
        my showEphemeralMessage("Loading secrets into ENV can be super simple!")
        delay 1
        my showEphemeralMessage("Eg put your secrets in the the keychain.")
        delay 1
        my typeCommand("docker mysecret --help")
        delay 1
        my showEphemeralMessage("This CLI tool can help you with that.")
        delay 1
        my typeCommand("docker mysecret ls")
        delay 1
        my showEphemeralMessage("Let's add a new secret..")
        delay 1
        my typeCommand("docker mysecret set GH_TOKEN=123456789")
        delay 1
        my typeCommand("docker mysecret ls")
        delay 1
        my showEphemeralMessage("We can inject it into a container..")
        delay 1
        my typeCommand("docker run -e GH_TOKEN= -dt --name demo busybox")
        delay 2
        my showEphemeralMessage("Let's double check!")
        delay 1
        my typeCommand("docker exec -it demo /bin/ash")
        delay 2
        my typeCommand("echo $GH_TOKEN")
        delay 3
        my showEphemeralMessage("And there it is!")
        delay 1
        my typeCommand("exit")
        delay 1
        my showEphemeralMessage("=> the secret engine will look empty ENVs for you")
        delay 1
        my typeCommand("docker rm -f demo")
        delay 2
        my showEphemeralMessage("But what if I just want an empty ENV?")
        delay 1
        my showEphemeralMessage("What if I want more explicit control?")
        delay 1
        my typeCommand("docker run -e EMPTY_ENV= -e GITHUB_TOKEN=se://GH_TOKEN -dt --name demo busybox")
        delay 2
        my showEphemeralMessage("Let's see what happened!")
        delay 1
        my typeCommand("docker exec -it demo /bin/ash")
        delay 2
        my typeCommand("echo $GITHUB_TOKEN")
        delay 3
        my showEphemeralMessage("And there it is!")
        delay 1
        my typeCommand("echo $EMPTY_ENV")
        delay 3
        my showEphemeralMessage("It's empty.")
        delay 1
        my typeCommand("exit")
        delay 1
        my showEphemeralMessage("Thanks for watching!")
        delay 1
    end tell
end tell

on typeCommand(message)
    set theChars to characters of message
    repeat with c in theChars
        tell application "System Events"
            keystroke c
        end tell
        delay 0.1
    end repeat
    delay 0.5
    tell application "System Events"
        keystroke return
    end tell
end typeCommand


on showEphemeralMessage(message)
    set theChars to characters of message
    repeat with c in theChars
        tell application "System Events"
            keystroke c
        end tell
        delay 0.05
    end repeat

    delay 1

    set charList to characters of message
    repeat with i from 1 to (count of charList)
        tell application "System Events"
            key code 51 -- backspace key
        end tell
        delay 0.025
    end repeat
end showEphemeralMessage