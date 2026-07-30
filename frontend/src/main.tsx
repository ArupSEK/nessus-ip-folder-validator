import React from "react";
import ReactDOM from "react-dom/client";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import type { PaletteMode } from "@mui/material";
import App from "./App";

function RootApp() {
  const [mode, setMode] = React.useState<PaletteMode>("dark");

  const theme = React.useMemo(
    () =>
      createTheme({
        palette: {
          mode,
          primary: { main: "#0f9d8a" },
          secondary: { main: "#d97706" },
          background:
            mode === "dark"
              ? { default: "#0c1117", paper: "#121923" }
              : { default: "#eef2f6", paper: "#ffffff" }
        },
        shape: {
          borderRadius: 8
        },
        typography: {
          fontFamily: "Inter, Segoe UI, sans-serif"
        }
      }),
    [mode]
  );

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <App mode={mode} onToggleColorMode={() => setMode((current) => (current === "dark" ? "light" : "dark"))} />
    </ThemeProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RootApp />
  </React.StrictMode>
);
