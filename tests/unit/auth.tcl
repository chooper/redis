# test no configured passwords
start_server {tags {"auth"}} {
    test {AUTH fails if there is no password configured server side} {
        catch {r auth foo} err
        set _ $err
    } {ERR*no password*}
}

# test one password
start_server {tags {"auth"} overrides {requirepass foobar}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given} {
        r auth foobar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server} {
        r set foo 100
        r incr foo
    } {101}
}

# specifying the same password multiple times is allowable
start_server {tags {"auth"} overrides {requirepass {foobar foobar}}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given} {
        r auth foobar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server} {
        r set foo 100
        r incr foo
    } {101}
}

# test two different passwords
start_server {tags {"auth"} overrides {requirepass {foo bar}}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the first password is given} {
        r auth foo
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server (first password)} {
        r set foo 100
        r incr foo
    } {101}

    test {AUTH succeeds when the second password is given} {
        r auth bar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server (second password)} {
        r set foo 100
        r incr foo
    } {101}
}

# test config setting passwords
start_server {tags {"auth"}} {
    test {CONFIG SET requires a password once one has been set} {
        r config set requirepass foobar
        catch {r set foo 100} err
        set _ $err
    } {NOAUTH*}

    test {CONFIG SET goes from no password to one password with unsuccessful auth} {
        catch {r auth wrong} err
        set _ $err
    } {ERR*invalid password}

    test {CONFIG SET goes from no password to one password with successful auth} {
        r auth foobar
    } {OK}
}

start_server {tags {"auth"}} {
    test {CONFIG SET goes from no password to two passwords with unsuccessful auth} {
        r config set requirepass "foobar bizbaz"
        catch {r auth wrong} err
        set _ $err
    } {ERR*invalid password}

    test {CONFIG SET goes from no password to two passwords with successful auth} {
        r auth foobar
        r auth bizbaz
    } {OK}
}

start_server {tags {"auth"}} {
    test {CONFIG SET denies passwords that are too long} {
        # (REDIS_AUTHPASS_MAX_LEN+1) = 513 chars
        catch {r config set requirepass AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA} err
        set _ $err
    } {ERR Invalid argument*}

    test {CONFIG SET denies too many passwords} {
        # (REDIS_REQUIREPASS_MAX+1) = 9 passwords
        catch {r config set requirepass "foobar1 foobar2 foobar3 foobar4 foobar5 foobar6 foobar7 foobar8 foobar9"} err
        set _ $err
    } {ERR Invalid argument*}

    test {CONFIG SET allows setting the same passwords} {
        r config set requirepass "foobar foobar"
        r auth foobar
    } {OK}
}

