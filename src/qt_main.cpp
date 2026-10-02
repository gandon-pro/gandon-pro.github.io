#include "gandon/core.hpp"

#include <QApplication>
#include <QFileDialog>
#include <QMainWindow>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <iomanip>
#include <memory>
#include <sstream>

class GandonWindow final : public QMainWindow {
public:
    GandonWindow() {
        setWindowTitle("Gandon-PRO - Native Disassembler");
        resize(1400, 850);
        setStyleSheet(R"(
            QMainWindow, QWidget { background: #1e2228; color: #d7e4ee; }
            QMenuBar, QMenu { background: #252a31; color: #d7e4ee; }
            QMenu::item:selected { background: #1976b8; }
            QTreeWidget, QPlainTextEdit { background: #181b20; border: 1px solid #38424d; }
            QTreeWidget::item:selected { background: #19527b; }
            QTabWidget::pane { border: 1px solid #38424d; }
            QTabBar::tab { background: #252a31; padding: 8px 18px; }
            QTabBar::tab:selected { background: #1976b8; }
            QStatusBar { background: #0878bd; color: white; }
        )");

        auto* open = menuBar()->addAction("Open binary...");
        open->setShortcut(QKeySequence("Ctrl+O"));
        connect(open, &QAction::triggered, this, &GandonWindow::openBinary);
        auto* refresh = menuBar()->addAction("Refresh");
        refresh->setShortcut(QKeySequence("F5"));
        connect(refresh, &QAction::triggered, this, &GandonWindow::refreshView);
        menuBar()->addAction("Exit", this, &QWidget::close);

        tree_ = new QTreeWidget;
        tree_->setHeaderLabels({"Functions / Sections", "Address"});
        tree_->setMinimumWidth(280);
        listing_ = new QPlainTextEdit;
        listing_->setReadOnly(true);
        listing_->setLineWrapMode(QPlainTextEdit::NoWrap);
        listing_->setFont(QFont("Cascadia Mono", 10));
        auto* tabs = new QTabWidget;
        tabs->addTab(listing_, "Gandon Text Listing");
        auto* xrefs = new QPlainTextEdit;
        xrefs->setReadOnly(true);
        xrefs->setFont(QFont("Cascadia Mono", 10));
        tabs->addTab(xrefs, "XREFs");
        xrefs_ = xrefs;
        auto* split = new QSplitter;
        split->addWidget(tree_);
        split->addWidget(tabs);
        split->setStretchFactor(1, 1);
        setCentralWidget(split);
        statusBar()->showMessage("Ready - open an EXE or DLL");
    }

private:
    void openBinary() {
        const auto path = QFileDialog::getOpenFileName(this, "Open binary", {}, "Windows binaries (*.exe *.dll);;All files (*.*)");
        if (path.isEmpty()) return;
        gandon::BinaryImage image;
        std::string error;
        if (!image.load(path.toStdWString(), error)) {
            QMessageBox::critical(this, "Load error", QString::fromStdString(error));
            return;
        }
        database_ = std::make_unique<gandon::AnalysisDatabase>(std::move(image));
        database_->discover_basic_xrefs();
        setWindowTitle("Gandon-PRO - " + path);
        refreshView();
        statusBar()->showMessage(QString("Loaded: %1 | %2 functions | %3 XREFs")
            .arg(path).arg(database_->functions().size()).arg(database_->xrefs().size()));
    }

    void refreshView() {
        if (!database_) return;
        tree_->clear();
        auto* sections = new QTreeWidgetItem(tree_, {"Sections", ""});
        for (const auto& section : database_->image().sections) {
            new QTreeWidgetItem(sections, {QString::fromStdString(section.name),
                QString("0x%1").arg(section.rva, 0, 16)});
        }
        sections->setExpanded(true);
        auto* functions = new QTreeWidgetItem(tree_, {"Functions", ""});
        for (const auto& function : database_->functions()) {
            new QTreeWidgetItem(functions, {QString::fromStdString(function.name),
                QString("0x%1").arg(function.start, 0, 16)});
        }
        functions->setExpanded(true);
        std::ostringstream listing;
        listing << "Entry point: 0x" << std::hex << database_->image().entry_point << "\n\n";
        for (const auto& instruction : gandon::decode_x64(database_->image(), database_->image().entry_point, 200)) {
            listing << "0x" << std::hex << instruction.address << "  "
                    << instruction.mnemonic << " " << instruction.operands << "\n";
        }
        listing_->setPlainText(QString::fromStdString(listing.str()));
        std::ostringstream xref_text;
        for (const auto& xref : database_->xrefs()) {
            xref_text << "0x" << std::hex << xref.from << " -> 0x" << xref.to << "  " << xref.kind << "\n";
        }
        xrefs_->setPlainText(QString::fromStdString(xref_text.str()));
    }

    QTreeWidget* tree_{};
    QPlainTextEdit* listing_{};
    QPlainTextEdit* xrefs_{};
    std::unique_ptr<gandon::AnalysisDatabase> database_;
};

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    GandonWindow window;
    window.show();
    return app.exec();
}
