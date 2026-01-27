#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "HexApp.h"
#include "HexDialog.h"
#include "HexStack.h"
#include "LineInputHandler.h"

namespace {

const char* GkHexVersion = "v0.7.4";

volatile sig_atomic_t g_sigintRequested = 0;

extern "C" void onSigInt(int)
{
    g_sigintRequested = 1;
}


std::string joinCommand ( const std::string & exe, const std::vector<std::string> & args )
{
    std::ostringstream oss;
    oss << exe;
    for ( const auto & a : args ) {
        oss << ' ';
        // lightweight quoting for display only
        if ( a.find(' ') != std::string::npos ) {
            oss << '"' << a << '"';
        } else {
            oss << a;
        }
    }
    return oss.str();
}


std::string fitToWidth ( const std::string & s, int width )
{
    if ( width <= 0 ) {
        return s;
    }
    // Leave 1 column of slack to avoid bottom-right edge quirks.
    const int maxLen = width - 1;
    if ( maxLen <= 0 || static_cast<int>(s.size()) <= maxLen ) {
        return s;
    }
    if ( maxLen <= 3 ) {
        return s.substr(0, static_cast<size_t>(maxLen));
    }
    return s.substr(0, static_cast<size_t>(maxLen - 3)) + "...";
}


std::vector<std::string> splitArgs ( const std::string & input )
{
    std::vector<std::string> out;
    std::string cur;

    enum class Mode { Normal, SingleQuote, DoubleQuote };
    Mode mode = Mode::Normal;
    bool escape = false;

    auto flush = [&]() {
        if ( ! cur.empty() ) {
            out.push_back(cur);
            cur.clear();
        }
    };

    for ( char c : input ) {
        if ( escape ) {
            cur.push_back(c);
            escape = false;
            continue;
        }

        if ( mode != Mode::SingleQuote && c == '\\' ) {
            escape = true;
            continue;
        }

        if ( mode == Mode::Normal ) {
            if ( c == '\'' ) {
                mode = Mode::SingleQuote;
                continue;
            }
            if ( c == '\"' ) {
                mode = Mode::DoubleQuote;
                continue;
            }
            if ( c == ' ' || c == '\t' || c == '\n' || c == '\r' ) {
                flush();
                continue;
            }
            cur.push_back(c);
        } else if ( mode == Mode::SingleQuote ) {
            if ( c == '\'' ) {
                mode = Mode::Normal;
                continue;
            }
            cur.push_back(c);
        } else {
            // DoubleQuote
            if ( c == '"' ) {
                mode = Mode::Normal;
                continue;
            }
            cur.push_back(c);
        }
    }

    flush();
    return out;
}

} // namespace

namespace gkhextrace {

class GkHexTraceApp final : public hexes::HexApp 
{
  public:

    GkHexTraceApp(std::string gktracePath, std::vector<std::string> gktraceArgs)
      : _gktracePath(std::move(gktracePath)), _gktraceArgs(std::move(gktraceArgs))
    {}

    ~GkHexTraceApp() override
    {
        stopChild();
    }

    void 
    run() override
    {
        // Intercept SIGINT so Ctrl-C can be used to interrupt the running
        // gktrace process without killing the UI.
        std::signal(SIGINT, onSigInt);

        this->setCursor(0);
        this->setBorderColor(hexes::HEX_WHITE);
        this->setBorderActiveColor(hexes::HEX_GREEN);

        _consoleHeight = 4;
        _statusHeight  = 2;
        _titleHeight   = 1;

        _mainStack = new hexes::HexStack(
            "main-stack",
            LINES - _statusHeight - _consoleHeight - _titleHeight,
            COLS,
            _titleHeight,
            0);
        // The HexStack itself is hidden and borderless; its *current child panel*
        // is what draws the border. Set stack border colors so new panels inherit
        // them, and keep active border green for focused indication.
        _mainStack->setBorderColor(hexes::HEX_WHITE);
        _mainStack->setBorderActiveColor(hexes::HEX_GREEN);
        this->addPanel(_mainStack);

        _statusPanel = this->createPanel(
            "status",
            _statusHeight,
            COLS,
            LINES - _statusHeight - _consoleHeight,
            0);
        _statusPanel->setDrawBorder(false);
        _statusPanel->setDrawTitle(false);
        _statusPanel->setTextColor(hexes::HEX_GREEN);

        _consolePanel = this->createPanel(
            "console",
            _consoleHeight,
            COLS,
            LINES - _consoleHeight,
            0);
        _consolePanel->setDrawBorder(false);
        _consolePanel->setDrawTitle(false);
        _consolePanel->setInputHandler(new hexes::LineInputHandler());
        _consoleInput = static_cast<hexes::LineInputHandler*>(_consolePanel->getInputHandler());

        _prompt = "gktrace> ";
        _consolePanel->addText(_prompt);
        _consoleInput->setPrefix(_prompt);

        auto* first = _mainStack->currentPanel();
        if ( first ) {
            first->enableScroll(true);
            first->setMaxLines(15000);
            first->setDrawBorder(true);
        }

        updateMainTitles();

        const std::string top = std::string("  gkhextrace  -  ") + GkHexVersion;
        this->print(0, 1, top, hexes::HEX_RED, hexes::HEX_BOLD);

        this->setFocus(_consolePanel);
        syncMainFocusIndicator();
        this->timeout(100);

        if ( ! _gktraceArgs.empty() ) {
            startChild();
        } else if ( auto * p = currentCapturePanel() ) {
            p->addText("-- idle: type gktrace args in the bottom console and press ENTER --");
        }
        renderStatus();

        bool quit = false;
        bool wcmd = false;
        while ( ! quit ) {
            if ( g_sigintRequested ) {
                g_sigintRequested = 0;
                interruptChild();
                renderStatus();
            }

            drainOutput();

            if ( this->resized() ) {
                resize();
                renderStatus();
            }

            this->draw();

            // IMPORTANT: Don't use HexApp::poll() here.
            // HexApp::poll() will try polling every panel when the focused panel
            // returns ERR, and since ncurses input is global, that can cause
            // non-focused panels to consume keystrokes.
            // This shows up as "only a few characters captured" in the console.
            hexes::HexPanel* cur = this->getPanel();
            const int ch = ( cur != nullptr ) ? cur->poll() : ERR;
            if ( ch == KEY_RESIZE && this->resized() ) {
                resize();
                renderStatus();
                continue;
            }
            if ( ch == ERR ) {
                continue;
            }

            // If the terminal is in raw mode (or on some keymaps), Ctrl-C can
            // arrive as an input character instead of SIGINT.
            if ( ch == 3 /* ETX */ ) {
                interruptChild();
                renderStatus();
                continue;
            }

            // Global window command: CTRL-w then UP/DOWN switches focus.
            if ( wcmd ) {
                wcmd = false;
                if ( _consoleInput ) {
                    _consoleInput->setParse(true);
                }
                if ( ch == KEY_DOWN ) {
                    this->setFocusNext();
                    syncMainFocusIndicator();
                } else if ( ch == KEY_UP ) {
                    this->setFocusPrev();
                    syncMainFocusIndicator();
                }
                renderStatus();
                continue;
            }

            if ( ch == hexes::HEX_KEY_WINDOW ) {
                wcmd = true;
                if ( cur == _consolePanel && _consoleInput ) {
                    _consoleInput->setParse(false);
                }
                renderStatus();
                continue;
            }

            // Quick jump to the command prompt.
            if ( ch == ':' ) {
                this->setFocus(_consolePanel);
                syncMainFocusIndicator();
                renderStatus();
                continue;
            }

            // Console input takes priority when focused.
            if ( cur == _consolePanel && _consoleInput ) {
                if ( _consoleInput->isReady() ) {
                    std::string cmdline = _consoleInput->getLine();

                    // Reset handler ready state + push history (no-op key).
                    _consoleInput->handleInput(_consolePanel, KEY_RIGHT);

                    _consolePanel->setText(_prompt);
                    _consoleInput->setPrefix(_prompt);

                    handleConsoleCommand(cmdline, quit);
                    renderStatus();
                    continue;
                }

                // If the line is empty, allow quick quit/help.
                if ( _consoleInput->getLine().empty() ) {
                    if ( ch == 'q' || ch == 'Q' ) {
                        quit = true;
                        continue;
                    }
                    if ( ch == 'h' || ch == '?' ) {
                        showHelp();
                        renderStatus();
                        continue;
                    }
                }

                // When focused on the console, treat remaining keys as input.
                continue;
            }

            if ( ch == 'q' || ch == 'Q' ) {
                quit = true;
            } else if ( ch == 'h' || ch == '?' ) {
                showHelp();
                renderStatus();
            } else if ( ch == 'n' ) {
                auto* p = _mainStack->createPanel();
                if ( p ) {
                    p->enableScroll(true);
                    p->setMaxLines(5000);
                    p->setDrawBorder(true);
                    p->addText("-- new panel created; capture continues here --");
                    updateMainTitles();
                    syncMainFocusIndicator();
                    renderStatus();
                }
            } else if ( ch == 'k' ) {
                if ( _mainStack->killCurrentPanel() ) {
                    updateMainTitles();
                    syncMainFocusIndicator();
                    renderStatus();
                }
            } else if ( ch == KEY_RIGHT || ch == '\t' ) {
                _mainStack->nextPanel();
                updateMainTitles();
                syncMainFocusIndicator();
                renderStatus();
            } else if ( ch == KEY_LEFT ) {
                _mainStack->prevPanel();
                updateMainTitles();
                syncMainFocusIndicator();
                renderStatus();
            } else if ( ch == 's' || ch == 'S' ) {
                saveCurrentPanel();
                renderStatus();
            } else if ( ch == KEY_UP ) {
                if (auto* p = currentCapturePanel()) {
                    p->scrollUp();
                }
            } else if ( ch == KEY_DOWN ) {
                if (auto* p = currentCapturePanel()) {
                    p->scrollDown();
                }
            } else if ( ch == 'c' || ch == 'C' ) {
                if (auto* p = currentCapturePanel()) {
                    p->clear();
                }
            }
        }
    }

  protected:
    void resize() override
    {
        if ( !_mainStack || !_statusPanel || !_consolePanel ) {
            return;
        }

        const int ht = this->height();
        const int wd = this->width();

        _mainStack->resize(ht - _statusHeight - _consoleHeight - _titleHeight, wd);
        _mainStack->moveWindow(_titleHeight, 0);

        _statusPanel->resize(_statusHeight, wd);
        _statusPanel->erase();
        _statusPanel->moveWindow(ht - _statusHeight - _consoleHeight, 0);

        _consolePanel->resize(_consoleHeight, wd);
        _consolePanel->erase();
        _consolePanel->moveWindow(ht - _consoleHeight, 0);
        _consolePanel->setText(_prompt);
        if ( _consoleInput ) {
            _consoleInput->setPrefix(_prompt);
        }

        this->print(0, 1, std::string("  gktrace_hexes  -  libhexes ") + LIBHEXES_VERSION, hexes::HEX_RED, hexes::HEX_BOLD);
        updateMainTitles();
    }

  private:
    void interruptChild()
    {
        if ( _childPid <= 0 ) {
            if ( _statusPanel ) {
                _statusPanel->addText("interrupt: no running gktrace");
            }
            return;
        }

        // Prefer signaling the child's process group so any descendants are
        // interrupted too.
        const pid_t target = (_childHasOwnPgrp ? -_childPid : _childPid);
        ::kill(target, SIGINT);

        if ( auto* p = currentCapturePanel() ) {
            p->addText("-- interrupt (SIGINT) sent --");
        }
    }

    void syncMainFocusIndicator()
    {
        // libhexes focus is tracked at the HexPanel level; HexStack is a panel
        // wrapper whose current child draws the border. To make focus obvious,
        // propagate focus to the currently visible child panel whenever the
        // app focus is on the main stack.
        auto* focused = this->getPanel();
        auto* cur = currentCapturePanel();
        if ( ! cur ) {
            return;
        }

        if ( focused == _mainStack ) {
            // Ensure border uses our active color.
            cur->setBorderActiveColor(hexes::HEX_GREEN);
            cur->setBorderColor(hexes::HEX_WHITE);
            cur->setFocus();
        } else {
            cur->unsetFocus();
        }
    }

    std::string focusedWindowName()
    {
        auto* focused = this->getPanel();
        if ( focused == _mainStack ) {
            return "OUTPUT";
        }
        if ( focused == _consolePanel ) {
            return "CONSOLE";
        }
        if ( focused == _statusPanel ) {
            return "STATUS";
        }
        return focused ? focused->getPanelName() : std::string("(none)");
    }

    hexes::HexPanel* currentCapturePanel() const
    {
        return _mainStack ? _mainStack->currentPanel() : nullptr;
    }

    void updateMainTitles()
    {
        if ( ! _mainStack ) {
            return;
        }

        const size_t total = _mainStack->panelCount();
        for ( size_t i = 0; i < total; ++i ) {
            auto* p = _mainStack->panelAt(i);
            if ( ! p ) {
                continue;
            }
            std::ostringstream t;
            t << " Output [" << (i + 1) << "/" << total << "] ";
            p->setWindowTitle(t.str(), hexes::HEX_GREEN);
        }

        // Ensure new panels inherit the stack's border colors.
        _mainStack->syncPanelColors();
    }

    void renderStatus()
    {
        if ( ! _statusPanel ) {
            return;
        }

        _statusPanel->clear();

        std::ostringstream line1;
        line1 << "Focus: " << focusedWindowName()
              << " | : console | Ctrl-w Up/Down focus | n new k kill | Tab next Left prev | s save c clear q quit";

        std::ostringstream line2;
        if ( _childPid > 0 ) {
            line2 << "Running: " << joinCommand(_gktracePath, _gktraceArgs);
        } else {
            line2 << "Idle: type args and press ENTER";
        }

        const int wd = _statusPanel->width();
        _statusPanel->addText(fitToWidth(line1.str(), wd));
        _statusPanel->addText(fitToWidth(line2.str(), wd));
    }

    void handleConsoleCommand(const std::string& cmdline, bool& quit)
    {
        auto tokens = splitArgs(cmdline);
        if ( tokens.empty() ) {
            return;
        }

        const std::string& verb = tokens[0];
        if ( verb == "/quit" || verb == "quit" || verb == "exit" ) {
            quit = true;
            return;
        }
        if ( verb == "/help" || verb == "help" || verb == "?" ) {
            showHelp();
            return;
        }

        // Treat the line as gktrace args; if user included the binary name, drop it.
        if ( ! tokens.empty() && (tokens[0] == "gktrace" || tokens[0].ends_with("/gktrace")) ) {
            tokens.erase(tokens.begin());
        }

        if ( auto* p = currentCapturePanel() ) {
            p->addText(std::string("-- exec: ") + joinCommand(_gktracePath, tokens));
        }

        restartChild(tokens);
    }

    void restartChild(const std::vector<std::string>& args)
    {
        stopChild();
        _gktraceArgs = args;
        startChild();
    }

    void showHelp()
    {
        std::string intro = "gktrace_hexes help";
        hexes::HexDialog d("help", hexes::HexString(intro, hexes::HEX_CYAN, hexes::HEX_BOLD));
        d.setDrawTitle(false);
        d.setTextColor(hexes::HEX_WHITE);
        d.setBorderColor(hexes::HEX_GREEN);
        d.addText("\nPanels:\n", hexes::HEX_GREEN, hexes::HEX_BOLD);
        d.addText("  n        create a new output panel (capture goes there)\n");
        d.addText("  TAB/RIGHT  switch to next panel\n");
        d.addText("  LEFT     switch to previous panel\n");
        d.addText("  k        kill current panel\n\n");
        d.addText("Focus:\n", hexes::HEX_GREEN, hexes::HEX_BOLD);
        d.addText("  CTRL-w then UP/DOWN switches focus between windows\n\n");
        d.addText("Console:\n", hexes::HEX_GREEN, hexes::HEX_BOLD);
        d.addText("  Press ':' to jump focus to the console\n");
        d.addText("  Type gktrace arguments and press ENTER to (re)start capture\n");
        d.addText("  You may also type: gktrace <args...>\n\n");
        d.addText("Output:\n", hexes::HEX_GREEN, hexes::HEX_BOLD);
        d.addText("  UP/DOWN  scroll\n");
        d.addText("  c        clear panel\n");
        d.addText("  s        save current panel to a file\n\n");
        d.addText("General:\n", hexes::HEX_GREEN, hexes::HEX_BOLD);
        d.addText("  q        quit\n");
        d.addText("\n<OK>", hexes::HEX_CYAN, hexes::HEX_BOLD);
        d.showDialog();
    }

    void saveCurrentPanel()
    {
        auto* p = currentCapturePanel();
        if ( ! p ) {
            return;
        }

        _statusPanel->addText("-- saving current panel --");

        hexes::HexDialog d("save", hexes::HexString("Save panel output", hexes::HEX_CYAN, hexes::HEX_BOLD));
        d.setDrawTitle(false);
        d.setTextColor(hexes::HEX_WHITE);
        d.setBorderColor(hexes::HEX_GREEN);
        d.echoResults(true);
        d.setMaxInput(32);
        d.addText("\nEnter filename to save current panel:\n\n", hexes::HEX_WHITE, hexes::HEX_NORMAL);
        d.showDialog();

        std::string out = d.getResult();
        if ( out.empty() )
            return;

        std::ofstream ofs(out, std::ios::out | std::ios::trunc);
        if ( ! ofs ) {
            _statusPanel->addText(std::string("save failed: ") + std::strerror(errno));
            return;
        }

        for ( const auto & hx : p->getTextList() ) {
            ofs << hx.str() << "\n";
        }

        if ( _statusPanel ) {
            _statusPanel->addText(std::string("saved: ") + out);
        }

        return;
    }


    void startChild()
    {
        if ( _childPid > 0 ) {
            return;
        }

        int pipefd[2] = {-1, -1};
        if (pipe(pipefd) != 0) {
            if ( _statusPanel ) {
                _statusPanel->addText(std::string("pipe() failed: ") + std::strerror(errno));
            }
            return;
        }

        const pid_t pid = fork();
        if ( pid == 0 ) {
            // child
            // Put gktrace in its own process group so Ctrl-C can be handled by
            // the UI and forwarded intentionally.
            ::setpgid(0, 0);
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::dup2(pipefd[1], STDERR_FILENO);
            ::close(pipefd[0]);
            ::close(pipefd[1]);

            std::vector<char*> argv;
            argv.reserve(_gktraceArgs.size() + 2);
            argv.push_back(const_cast<char*>(_gktracePath.c_str()));
            for (auto& s : _gktraceArgs) {
                argv.push_back(const_cast<char*>(s.c_str()));
            }
            argv.push_back(nullptr);

            ::execvp(argv[0], argv.data());
            _exit(127);
        }

        // parent
        ::close(pipefd[1]);

        if ( pid < 0 ) {
            ::close(pipefd[0]);
            if ( _statusPanel ) {
                _statusPanel->addText(std::string("fork() failed: ") + std::strerror(errno));
            }
            return;
        }

        // Parent: also try to ensure the child is in its own process group.
        // If this fails, we will fall back to signaling the single PID.
        _childHasOwnPgrp = (::setpgid(pid, pid) == 0);

        _childPid = pid;
        _childFd = pipefd[0];

        _stopReader.store(false);
        _reader = std::thread([this]() { readerLoop(); });

        if ( auto* p = currentCapturePanel() ) {
            p->addText(std::string("-- started: ") + joinCommand(_gktracePath, _gktraceArgs));
        }
    }

    void stopChild()
    {
        _stopReader.store(true);

        if ( _childPid > 0 ) {
            const pid_t target = (_childHasOwnPgrp ? -_childPid : _childPid);
            ::kill(target, SIGTERM);
        }

        if ( _childFd >= 0 ) {
            ::close(_childFd);
            _childFd = -1;
        }

        if ( _reader.joinable() ) {
            _reader.join();
        }

        if ( _childPid > 0 ) {
            int status = 0;
            ::waitpid(_childPid, &status, 0);
            _childPid = -1;
            _childHasOwnPgrp = false;
        }
    }

    void readerLoop()
    {
        std::string carry;
        std::array<char, 4096> buf{};

        while ( ! _stopReader.load() ) {
            if ( _childFd < 0 ) {
                break;
            }

            const ssize_t n = ::read(_childFd, buf.data(), buf.size());
            if ( n > 0 ) {
                carry.append(buf.data(), static_cast<size_t>(n));

                size_t pos = 0;
                while ( true ) {
                    const size_t nl = carry.find('\n', pos);
                    if (nl == std::string::npos) {
                        carry.erase(0, pos);
                        break;
                    }
                    std::string line = carry.substr(pos, nl - pos);
                    pos = nl + 1;

                    std::lock_guard<std::mutex> lk(_pendingMu);
                    _pendingLines.push_back(std::move(line));
                }
            } else if ( n == 0 ) {
                // EOF
                break;
            } else {
                if ( errno == EINTR ) {
                    continue;
                }
                break;
            }
        }

        if ( ! carry.empty() ) {
            std::lock_guard<std::mutex> lk(_pendingMu);
            _pendingLines.push_back(std::move(carry));
        }

        // Note: we intentionally do not touch ncurses objects here.
    }

    void drainOutput()
    {
        auto* p = currentCapturePanel();
        if ( ! p ) {
            return;
        }

        std::deque<std::string> local;
        {
            std::lock_guard<std::mutex> lk(_pendingMu);
            if ( _pendingLines.empty() ) {
                return;
            }
            local.swap(_pendingLines);
        }

        for ( auto & line : local ) {
            p->addText(line);
        }
    }

    std::string _gktracePath;
    std::vector<std::string> _gktraceArgs;

    hexes::HexStack* _mainStack{nullptr};
    hexes::HexPanel* _statusPanel{nullptr};
    hexes::HexPanel* _consolePanel{nullptr};
    hexes::LineInputHandler* _consoleInput{nullptr};

    std::string _prompt;

    int _statusHeight{2};
    int _titleHeight{1};
    int _consoleHeight{4};

    pid_t _childPid{-1};
    int _childFd{-1};
    bool _childHasOwnPgrp{false};

    std::thread _reader;
    std::atomic<bool> _stopReader{false};
    std::mutex _pendingMu;
    std::deque<std::string> _pendingLines;
};

} // namespace gktrace_hexes

int main ( int argc, char** argv )
{
    std::string gktraceBin = "./gktrace";
    if ( const char* env = std::getenv("GKTRACE_BIN") ) {
        if ( env[0] != '\0' ) {
            gktraceBin = env;
        }
    }

    std::vector<std::string> gktraceArgs;
    gktraceArgs.reserve(static_cast<size_t>(argc > 1 ? argc - 1 : 0));
    for ( int i = 1; i < argc; ++i ) {
        gktraceArgs.emplace_back(argv[i]);
    }

    gkhextrace::GkHexTraceApp app(std::move(gktraceBin), std::move(gktraceArgs));
    app.run();
    return 0;
}
