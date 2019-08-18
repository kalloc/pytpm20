#include <Python.h>
#include "utils.h"

static char py_getrandom_docstring[] = "Get random bytes";
static PyObject *py_getrandom(PyObject *self, PyObject *args);

