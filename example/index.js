/**
 * @format
 */

// First, before the library loads: PS* signing needs crypto.getRandomValues,
// and noble decides once, when a curve module loads, whether it has one.
import 'react-native-get-random-values';
import { AppRegistry } from 'react-native';
import App from './App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
