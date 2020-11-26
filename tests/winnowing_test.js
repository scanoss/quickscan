const win = require('../winnowing')

test('filter node_modules folders', () => {
  expect(win.is_filtered_dir('/root/node_modules/stuff')).toBe(true);
  expect(win.is_filtered_dir("C:\\node_modules\\stuff", '\\')).toBe(true)
})